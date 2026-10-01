"""Dossiê probatório de um documento, verificável SEM o sistema em produção.

O ZIP contém:
- todas as versões do PDF (original, emitido/selado, com o registro, comprovante)
  e eventuais arquivos adicionais referenciados na evidência;
- ``evidencia.json`` (JSON canônico; o SHA-256 dele está no comprovante e na
  assinatura PAdES de aceite);
- ``auditoria/segmento.jsonl``: o segmento CONTÍNUO da cadeia de auditoria do
  primeiro evento do documento até a primeira âncora que o cobre (ou até a
  cabeça atual), com o payload exatamente como foi "hasheado";
- ``auditoria/ancoras/*.tsr``: os carimbos do tempo RFC 3161 das âncoras;
- ``termo/termo-vX.txt``: texto do termo de adesão referenciado;
- ``LEIA-ME.txt`` (receita de verificação) e ``verificar.py`` (script autônomo).
"""

from __future__ import annotations

import io
import json
import logging
import zipfile

from sqlalchemy import select
from sqlalchemy.orm import Session

from portal.audit import GENESIS, _event_payload, canonical_json, sha256_hex
from portal.models import AdhesionTerm, AuditAnchor, AuditEvent, Document
from portal.storage import Storage

MAX_SEGMENT_EVENTS = 50_000
log = logging.getLogger(__name__)

README = """DOSSIÊ PROBATÓRIO — Portal do Colaborador
=========================================

1. Integridade dos arquivos: o SHA-256 de cada PDF deve coincidir com o
   informado em manifesto.json (e, para o documento apresentado/final, com os
   campos sha256_* da evidencia.json).

2. Assinaturas: valide os PDFs no Verificador de Conformidade do ITI
   (https://validar.iti.gov.br) ou com qualquer validador PAdES. O comprovante
   embute evidencia.json e o PDF exatamente como apresentado ao colaborador.

3. Evidência: SHA-256(evidencia.json) deve ser igual ao "SHA-256 da evidência"
   impresso no comprovante e ao valor na razão da assinatura "AceiteColaborador".

4. Trilha de auditoria (auditoria/segmento.jsonl, uma linha por evento):
   hash = SHA-256( hash_anterior + "\\n" + JSON_canônico(payload) )
   onde JSON_canônico = json.dumps(payload, sort_keys=True,
   separators=(",", ":"), ensure_ascii=False). Cada evento deve apontar para o
   hash do anterior. O primeiro evento do segmento aponta para hash_anterior.

5. Âncoras (auditoria/ancoras/*.tsr): carimbos RFC 3161 emitidos por ACT sobre
   SHA-256("portal-auditoria:<evento>:<hash>"). Se o último evento do segmento
   for o evento ancorado e seu hash coincidir, o histórico até ali existia na
   data do carimbo (verifique o token com openssl ts -verify ou o validador da ACT).

O script verificar.py executa os passos 1, 3, 4 e a conferência do imprint das âncoras:
    python3 verificar.py
"""

VERIFY_SCRIPT = r'''#!/usr/bin/env python3
"""Verifica o dossiê sem depender do portal (Python 3.9+, apenas biblioteca padrão)."""
import hashlib, json, pathlib, sys

base = pathlib.Path(__file__).parent
ok = True
def sha(b): return hashlib.sha256(b).hexdigest()
def canon(o): return json.dumps(o, sort_keys=True, separators=(",", ":"), ensure_ascii=False)

man = json.loads((base / "manifesto.json").read_text(encoding="utf-8"))
for name, info in man["arquivos"].items():
    real = sha((base / name).read_bytes())
    good = real == info["sha256"]
    ok &= good
    print(("OK  " if good else "FALHA ") + f"arquivo {name}")
ev = base / "evidencia.json"
if ev.exists():
    print("SHA-256 da evidência:", sha(ev.read_bytes()), "(compare com o comprovante)")
lines = (base / "auditoria" / "segmento.jsonl").read_text(encoding="utf-8").splitlines()
prev = None
for line in lines:
    e = json.loads(line)
    if prev is not None and e["hash_anterior"] != prev:
        ok = False; print("FALHA encadeamento no evento", e["id"])
    calc = sha((e["hash_anterior"] + "\n" + canon(e["payload"])).encode("utf-8"))
    if calc != e["hash"]:
        ok = False; print("FALHA hash do evento", e["id"])
    prev = e["hash"]
print(f"Trilha: {len(lines)} eventos verificados")
for a in man.get("ancoras", []):
    imprint = hashlib.sha256(f"portal-auditoria:{a['evento']}:{a['hash']}".encode()).hexdigest()
    tsr = (base / a["arquivo"]).read_bytes()
    good = bytes.fromhex(imprint) in tsr
    ok &= good
    print(("OK  " if good else "FALHA ") + f"âncora do evento {a['evento']} (imprint no token)")
print("RESULTADO:", "ÍNTEGRO" if ok else "DIVERGÊNCIAS ENCONTRADAS")
sys.exit(0 if ok else 1)
'''


def _segment(db: Session, first_id: int) -> tuple[list[AuditEvent], AuditAnchor | None]:
    """Eventos contínuos de ``first_id`` até a primeira âncora que os cobre."""
    last_doc_event = first_id
    anchor = db.scalar(
        select(AuditAnchor)
        .where(AuditAnchor.head_event_id >= last_doc_event)
        .order_by(AuditAnchor.head_event_id)
    )
    upper = anchor.head_event_id if anchor else None
    q = select(AuditEvent).where(AuditEvent.id >= first_id).order_by(AuditEvent.id)
    if upper is not None:
        q = q.where(AuditEvent.id <= upper)
    events = list(db.scalars(q.limit(MAX_SEGMENT_EVENTS)))
    return events, anchor


def build_dossier(db: Session, storage: Storage, doc: Document) -> tuple[bytes, dict]:
    doc_events = db.scalars(
        select(AuditEvent).where(AuditEvent.document_id == doc.id).order_by(AuditEvent.id)
    ).all()
    first_id = doc_events[0].id if doc_events else 0
    last_doc_id = doc_events[-1].id if doc_events else 0
    segment, _ = _segment(db, first_id) if first_id else ([], None)
    # âncoras que cobrem o último evento do documento
    anchors = db.scalars(
        select(AuditAnchor)
        .where(AuditAnchor.head_event_id >= last_doc_id)
        .order_by(AuditAnchor.head_event_id)
        .limit(1)
    ).all()

    files: dict[str, dict] = {}
    manifest: dict = {
        "documento": doc.id,
        "codigo_verificacao": doc.verification_code,
        "status": doc.status,
        "arquivos": files,
        "eventos_do_documento": [e.id for e in doc_events],
        "segmento_auditoria": {
            "primeiro_evento": segment[0].id if segment else None,
            "ultimo_evento": segment[-1].id if segment else None,
            "hash_anterior_inicial": segment[0].prev_hash if segment else GENESIS,
            "truncado": len(segment) >= MAX_SEGMENT_EVENTS,
        },
        "ancoras": [],
    }
    buf = io.BytesIO()
    with zipfile.ZipFile(buf, "w", zipfile.ZIP_DEFLATED) as zf:

        def add_file(name: str, key: str | None, sha: str | None) -> None:
            if not key:
                return
            data = storage.get(key)
            zf.writestr(name, data)
            files[name] = {"sha256": sha or sha256_hex(data), "integro": sha256_hex(data) == sha}

        add_file("1-original.pdf", doc.original_key, doc.original_sha256)
        add_file("2-emitido-selado.pdf", doc.sealed_key, doc.sealed_sha256)
        add_file("3-com-registro.pdf", doc.final_key, doc.final_sha256)
        add_file("4-comprovante.pdf", doc.receipt_key, doc.receipt_sha256)
        evidence: dict = {}
        if doc.acceptance:
            zf.writestr("evidencia.json", doc.acceptance.evidence_json)
            evidence = json.loads(doc.acceptance.evidence_json)
            extra = (evidence.get("documento") or {}).get("arquivos_adicionais") or []
            for i, item in enumerate(extra, start=1):
                add_file(f"5-adicional-{i}.pdf", item.get("key"), item.get("sha256"))
            ds = evidence.get("docuseal") or {}
            add_file("6-trilha-docuseal.pdf", ds.get("trilha_key"), ds.get("trilha_sha256"))
            term = evidence.get("termo_adesao") or {}
            if term.get("versao"):
                t = db.scalar(select(AdhesionTerm).where(AdhesionTerm.version == term["versao"]))
                if t is not None:
                    zf.writestr(f"termo/termo-v{t.version}.txt", t.text)
        zf.writestr(
            "auditoria/segmento.jsonl",
            "\n".join(
                canonical_json(
                    {
                        "id": e.id,
                        "hash_anterior": e.prev_hash,
                        "hash": e.hash,
                        "payload": _event_payload(e),
                    }
                )
                for e in segment
            ),
        )
        for a in anchors:
            name = f"auditoria/ancoras/{a.head_event_id}.tsr"
            try:
                zf.writestr(name, storage.get(a.token_key))
            except Exception:  # noqa: BLE001
                log.exception("token da âncora %s indisponível (%s)", a.head_event_id, a.token_key)
                manifest["ancoras_indisponiveis"] = [
                    *manifest.get("ancoras_indisponiveis", []),
                    a.head_event_id,
                ]
                continue
            manifest["ancoras"].append(
                {"evento": a.head_event_id, "hash": a.head_hash, "arquivo": name, "act": a.tsa_url}
            )
        zf.writestr("manifesto.json", json.dumps(manifest, ensure_ascii=False, indent=2))
        zf.writestr("LEIA-ME.txt", README)
        zf.writestr("verificar.py", VERIFY_SCRIPT)
    return buf.getvalue(), manifest
