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
from portal.models import AuditAnchor, AuditChainHead
from portal.storage import Storage


def anchor_digest(head_event_id: int, head_hash: str) -> bytes:
    return hashlib.sha256(f"portal-auditoria:{head_event_id}:{head_hash}".encode()).digest()


def anchor_audit(db: Session, storage: Storage, timestamper, tsa_url: str) -> AuditAnchor:
    head = db.get(AuditChainHead, 1)
    if head is None:
        raise ValueError("trilha de auditoria vazia")
    report = audit.verify_chain(db)
    if not report.ok:
        raise ValueError(f"cadeia de auditoria inválida: {report.reason}")
    digest = anchor_digest(head.last_event_id, head.last_hash)
    token: cms.ContentInfo = asyncio.run(timestamper.async_timestamp(digest, "sha256"))
    der = token.dump()
    sha = hashlib.sha256(der).hexdigest()
    key = f"auditoria/ancoras/{head.last_event_id:012d}-{sha[:16]}.tsr"
    storage.put(key, der, content_type="application/timestamp-reply")
    anchor = AuditAnchor(
        head_event_id=head.last_event_id,
        head_hash=head.last_hash,
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
        data={"evento": head.last_event_id, "hash": head.last_hash, "token_sha256": sha},
    )
    db.commit()
    return anchor


def verify_anchor(anchor: AuditAnchor, token_der: bytes) -> bool:
    """Confere se o token carimbou exatamente o digest da cabeça registrada."""
    info = cms.ContentInfo.load(token_der)
    tst_info = info["content"]["encap_content_info"]["content"].parsed
    imprint = tst_info["message_imprint"]["hashed_message"].native
    return imprint == anchor_digest(anchor.head_event_id, anchor.head_hash)
