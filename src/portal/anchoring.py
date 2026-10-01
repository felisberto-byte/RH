"""Ancoragem da trilha de auditoria em carimbo do tempo (RFC 3161).

Periodicamente (ex.: diariamente via Cloud Scheduler + Cloud Run Job), o hash
da cabeça da cadeia de auditoria é carimbado por uma ACT. O token prova, por
terceiro, que toda a cadeia até aquele evento já existia naquele instante —
a empresa não consegue reescrever o histórico depois sem que isso seja
detectado. Custo: um carimbo por dia, em vez de um por evento.
"""

from __future__ import annotations

import asyncio
import hashlib

from asn1crypto import cms
from sqlalchemy.orm import Session

from portal import audit
from portal.models import AuditAnchor
from portal.storage import Storage


def anchor_digest(head_event_id: int, head_hash: str) -> bytes:
    return hashlib.sha256(f"portal-auditoria:{head_event_id}:{head_hash}".encode()).digest()


def anchor_audit(db: Session, storage: Storage, timestamper, tsa_url: str) -> AuditAnchor:
    # Retrato consistente: verifica a cadeia até a cabeça lida agora e ancora
    # exatamente esse evento (eventos gravados depois ficam para a próxima âncora).
    report = audit.verify_chain(db)
    if not report.ok:
        raise ValueError(f"cadeia de auditoria inválida: {report.reason}")
    if report.head_event_id == 0:
        raise ValueError("trilha de auditoria vazia")
    head_event_id, head_hash = report.head_event_id, report.head_hash
    db.rollback()  # não segura transação durante a chamada à ACT
    digest = anchor_digest(head_event_id, head_hash)
    token: cms.ContentInfo = asyncio.run(timestamper.async_timestamp(digest, "sha256"))
    der = token.dump()
    sha = hashlib.sha256(der).hexdigest()
    key = f"auditoria/ancoras/{head_event_id:012d}-{sha[:16]}.tsr"
    storage.put(key, der, content_type="application/timestamp-reply")
    anchor = AuditAnchor(
        head_event_id=head_event_id,
        head_hash=head_hash,
        tsa_url=tsa_url,
        token_key=key,
        token_sha256=sha,
    )
    db.add(anchor)
    audit.record(
        db,
        action="AUDITORIA_ANCORADA",
        actor_type="sistema",
        actor_ref="anchor-audit",
        data={"evento": head_event_id, "hash": head_hash, "token_sha256": sha},
    )
    db.commit()
    return anchor


def verify_anchor(anchor: AuditAnchor, token_der: bytes, trust_roots=None) -> dict:
    """Confere o token: imprint = digest da cabeça ancorada e assinatura da ACT
    íntegra (``trusted`` só é verdadeiro com as raízes da ACT informadas)."""
    from pyhanko.sign.validation.generic_cms import validate_tst_signed_data
    from pyhanko_certvalidator import ValidationContext

    expected = anchor_digest(anchor.head_event_id, anchor.head_hash)
    info = cms.ContentInfo.load(token_der)
    signed_data = info["content"]
    tst_info = signed_data["encap_content_info"]["content"].parsed
    imprint_ok = tst_info["message_imprint"]["hashed_message"].native == expected
    result = {
        "imprint_ok": imprint_ok,
        "intact": False,
        "valid": False,
        "trusted": False,
        "gen_time": str(tst_info["gen_time"].native),
    }
    try:
        roots = list(trust_roots or [])
        if not roots:
            # Sem as raízes da ACT configuradas, confere só a integridade
            # criptográfica usando o próprio certificado embutido no token.
            roots = [c.chosen for c in signed_data["certificates"] or []]
        vc = ValidationContext(trust_roots=roots, allow_fetching=False)
        status = asyncio.run(
            validate_tst_signed_data(signed_data, vc, expected_tst_imprint=lambda _alg: expected)
        )
        result.update(
            intact=bool(status["intact"]),
            valid=bool(status["valid"]),
            trusted=bool(status.get("trust_problem_indic") is None and trust_roots),
        )
    except Exception as exc:  # noqa: BLE001
        result["erro"] = str(exc)
    return result
