"""Conclusão de documentos assinados no DocuSeal (webhooks ``form.completed``
e ``form.declined``).

Ordem obrigatória das assinaturas (testado contra o DocuSeal CE 3.3): o
colaborador assina no DocuSeal **primeiro**; o selo PAdES com o e-CNPJ é
aplicado pelo portal **por último**, de forma incremental, sobre o PDF que o
DocuSeal devolve. Um selo aplicado antes seria removido/invalidado pelo
"achatamento" que o DocuSeal faz no PDF final.
"""

from __future__ import annotations

import logging
from datetime import UTC, datetime
from zoneinfo import ZoneInfo

from sqlalchemy import select
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import canonical_json, sha256_hex
from portal.config import Settings
from portal.db import utcnow
from portal.integrations.docuseal import DocusealClient, DocusealError
from portal.models import Acceptance, AuditEvent, DocStatus, Document, Engine
from portal.signing.pades import Sealer, SealingError
from portal.signing.receipt import ReceiptData, build_receipt_pdf
from portal.storage import Storage

log = logging.getLogger(__name__)

LEGAL_NOTE_DOCUSEAL = (
    "Assinatura eletrônica realizada na plataforma DocuSeal a partir de link de uso único "
    "aberto pelo colaborador autenticado no Portal do Colaborador (Active Directory). "
    "O PDF final recebeu selo PAdES com certificado ICP-Brasil da empresa após a conclusão. "
    "Meio de comprovação admitido pelas partes (MP nº 2.200-2/2001, art. 10, § 2º)."
)


def _parse_dt(value: str | None) -> datetime:
    if not value:
        return utcnow()
    return datetime.fromisoformat(value.replace("Z", "+00:00"))


def handle_event(
    db: Session,
    storage: Storage,
    client: DocusealClient,
    payload: dict,
    *,
    sealer: Sealer | None,
    settings: Settings,
) -> str:
    event = payload.get("event_type")
    data = payload.get("data") or {}
    if event not in ("form.completed", "form.declined"):
        return "ignorado"
    doc_id = str(data.get("external_id") or "")
    doc = db.execute(
        select(Document).where(Document.id == doc_id).with_for_update()
    ).scalar_one_or_none()
    if doc is None or doc.engine != Engine.DOCUSEAL:
        return "desconhecido"
    if doc.docuseal_submitter_id is None or data.get("id") != doc.docuseal_submitter_id:
        audit.record(
            db,
            action="DOCUSEAL_SUBMITTER_DIVERGENTE",
            actor_type="sistema",
            actor_ref="docuseal",
            document_id=doc.id,
            data={"recebido": data.get("id"), "esperado": doc.docuseal_submitter_id},
        )
        db.commit()
        return "submitter_divergente"
    if doc.status != DocStatus.PENDENTE:
        return "ja_processado"
    if sealer is None:
        # Sem o e-CNPJ não há como selar: 5xx faz o DocuSeal reenviar depois.
        raise DocusealError("certificado de assinatura não configurado")

    opened = db.scalar(
        select(AuditEvent)
        .where(AuditEvent.document_id == doc.id, AuditEvent.action == "DOCUSEAL_LINK_ABERTO")
        .order_by(AuditEvent.id.desc())
    )
    if opened is None:
        # Sem vínculo com uma sessão AD do portal: não aceitamos como manifestação.
        audit.record(
            db,
            action="DOCUSEAL_SEM_VINCULO_AD",
            actor_type="sistema",
            actor_ref="docuseal",
            document_id=doc.id,
            data={"evento": event},
        )
        db.commit()
        return "sem_vinculo_ad"

    at = _parse_dt(data.get("completed_at") or data.get("declined_at"))
    decision = "ACEITO" if event == "form.completed" else "RECUSADO"
    trail_key = trail_sha = None
    audit_url = data.get("audit_log_url") or (data.get("submission") or {}).get("audit_log_url")
    if audit_url:
        trail = client.download(audit_url)
        trail_sha = sha256_hex(trail)
        trail_key = f"documentos/{doc.id}/docuseal-trilha-{trail_sha[:16]}.pdf"
        if not storage.exists(trail_key):
            storage.put(trail_key, trail)

    final: bytes | None = None
    if decision == "ACEITO":
        documents = data.get("documents") or []
        if not documents:
            raise DocusealError("webhook sem documentos")
        signed = client.download(documents[0]["url"])
        signed_sha = sha256_hex(signed)
        try:
            final = sealer.seal_final(
                signed, reason=f"Selo da empresa sobre documento assinado no DocuSeal ({doc.id})"
            )
        except SealingError as exc:
            raise DocusealError(str(exc)) from exc
        final_sha = sha256_hex(final)
        doc.original_key = f"documentos/{doc.id}/docuseal-assinado-{signed_sha[:16]}.pdf"
        doc.original_sha256 = signed_sha
        doc.final_key = f"documentos/{doc.id}/final-{final_sha[:16]}.pdf"
        doc.final_sha256 = final_sha
        if not storage.exists(doc.original_key):
            storage.put(doc.original_key, signed)
        storage.put(doc.final_key, final)

    ctx = opened.data or {}
    evidence = {
        "versao": 1,
        "tipo": "manifestacao_eletronica_docuseal",
        "decisao": decision,
        "documento": {
            "id": doc.id,
            "titulo": doc.titulo,
            "codigo_verificacao": doc.verification_code,
            "sha256_assinado_docuseal": doc.original_sha256,
            "sha256_final": doc.final_sha256,
        },
        "signatario": {
            "nome": doc.employee.nome,
            "matricula": doc.employee.matricula,
            "ad": {
                "sAMAccountName": opened.actor_ref,
                "objectGUID": ctx.get("objectGUID"),
                "userPrincipalName": ctx.get("upn"),
                "dn": ctx.get("dn"),
            },
        },
        "portal": {
            "link_aberto_em_utc": audit.iso_utc(opened.occurred_at),
            "ip": opened.ip,
            "user_agent": opened.user_agent,
            "sessao_ref": ctx.get("sessao_ref"),
            "evento_auditoria": opened.id,
            "termo_adesao": ctx.get("termo_adesao"),
        },
        "docuseal": {
            "submitter_id": data.get("id"),
            "submission_id": data.get("submission_id"),
            # Atrás do balanceador do GCP, o DocuSeal pode registrar o IP do LB
            # (ver docs); o IP de referência é o capturado pelo portal.
            "ip": data.get("ip"),
            "user_agent": data.get("ua"),
            "aberto_em": data.get("opened_at"),
            "concluido_em": data.get("completed_at"),
            "recusa": data.get("decline_reason"),
            "trilha_key": trail_key,
            "trilha_sha256": trail_sha,
        },
    }
    evidence_json = canonical_json(evidence)
    evidence_sha = sha256_hex(evidence_json)

    tz = ZoneInfo(settings.timezone)
    opened_at = opened.occurred_at
    if opened_at.tzinfo is None:
        opened_at = opened_at.replace(tzinfo=UTC)
    receipt = build_receipt_pdf(
        ReceiptData(
            company_name=settings.company_name,
            company_cnpj=settings.company_cnpj,
            title="Comprovante de Assinatura Eletrônica"
            if decision == "ACEITO"
            else "Comprovante de Recusa",
            rows=[
                ("Documento", f"{doc.titulo} ({doc.document_type.nome})"),
                ("Código de verificação", doc.verification_code),
                ("SHA-256 do documento final", doc.final_sha256 or "—"),
                ("Colaborador", f"{doc.employee.nome} — matrícula {doc.employee.matricula}"),
                ("Usuário AD", f"{opened.actor_ref} ({ctx.get('upn') or '—'})"),
                ("objectGUID (AD)", ctx.get("objectGUID") or "—"),
                (
                    "Link aberto no portal",
                    f"{opened_at.astimezone(tz):%d/%m/%Y %H:%M:%S} · IP {opened.ip}",
                ),
                ("Concluído no DocuSeal", f"{at.astimezone(tz):%d/%m/%Y %H:%M:%S}"),
                ("Trilha DocuSeal (SHA-256)", trail_sha or "—"),
            ],
            declaration=doc.document_type.declaration_text,
            evidence_sha256=evidence_sha,
            verification_url=f"{settings.base_url.rstrip('/')}/verificar/{doc.verification_code}",
            legal_note=LEGAL_NOTE_DOCUSEAL,
        ),
        evidence_json,
        document_pdf=final if decision == "ACEITO" else None,
    )
    receipt = sealer.seal_receipt(receipt)
    doc.receipt_sha256 = sha256_hex(receipt)
    doc.receipt_key = f"documentos/{doc.id}/comprovante-{doc.receipt_sha256[:16]}.pdf"
    storage.put(doc.receipt_key, receipt)

    db.add(
        Acceptance(
            document_id=doc.id,
            employee_id=doc.employee_id,
            decision=decision,
            reason=data.get("decline_reason"),
            source="docuseal",
            ad_object_guid=ctx.get("objectGUID") or "",
            ad_username=opened.actor_ref,
            ad_upn=ctx.get("upn"),
            ip=str(opened.ip or data.get("ip") or "")[:45],
            user_agent=str(opened.user_agent or data.get("ua") or "")[:512],
            accepted_at=at,
            reauth_method="sessao_ad+link_docuseal",
            session_ref=ctx.get("sessao_ref") or "",
            document_sha256=doc.final_sha256 or "",
            declaration_text=doc.document_type.declaration_text,
            evidence_json=evidence_json,
            evidence_sha256=evidence_sha,
        )
    )
    doc.status = DocStatus.ASSINADO if decision == "ACEITO" else DocStatus.RECUSADO
    doc.completed_at = at
    audit.record(
        db,
        action="DOCUMENTO_ACEITO" if decision == "ACEITO" else "DOCUMENTO_RECUSADO",
        actor_type="colaborador",
        actor_ref=opened.actor_ref,
        document_id=doc.id,
        ip=opened.ip,
        user_agent=opened.user_agent,
        data={
            "origem": "docuseal",
            "sha256_final": doc.final_sha256,
            "sha256_comprovante": doc.receipt_sha256,
            "evidencia_sha256": evidence_sha,
            "ip_docuseal": data.get("ip"),
        },
    )
    db.commit()
    return "processado"
