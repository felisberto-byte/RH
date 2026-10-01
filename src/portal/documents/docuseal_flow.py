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


# Registrada quando o colaborador RECUSA no DocuSeal (nunca a declaração de concordância).
DECLINE_DECLARATION = (
    "Recusei a assinatura deste documento na plataforma DocuSeal pelo motivo informado."
)


def _link_event(db: Session, doc: Document, submitter_id) -> AuditEvent | None:
    """Evento DOCUSEAL_LINK_ABERTO do MESMO signatário que concluiu (o
    colaborador pode ter gerado mais de um link; vale o do envio concluído)."""
    events = db.scalars(
        select(AuditEvent)
        .where(AuditEvent.document_id == doc.id, AuditEvent.action == "DOCUSEAL_LINK_ABERTO")
        .order_by(AuditEvent.id.desc())
    ).all()
    for ev in events:
        if (ev.data or {}).get("submitter_id") == submitter_id:
            return ev
    return None


def _put(storage: Storage, key: str, data: bytes) -> None:
    # Chaves endereçadas pelo conteúdo: um reenvio do webhook não sobrescreve.
    if not storage.exists(key):
        storage.put(key, data)


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
        select(Document)
        .where(Document.id == doc_id)
        .with_for_update()
        .execution_options(populate_existing=True)
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
        db.rollback()
        return "ja_processado"
    if sealer is None:
        # Sem o e-CNPJ não há como selar: 5xx faz o DocuSeal reenviar depois.
        raise DocusealError("certificado de assinatura não configurado")

    opened = _link_event(db, doc, data.get("id"))
    if opened is None:
        # Sem vínculo com uma sessão AD do portal: não aceitamos como manifestação.
        audit.record(
            db,
            action="DOCUSEAL_SEM_VINCULO_AD",
            actor_type="sistema",
            actor_ref="docuseal",
            document_id=doc.id,
            data={"evento": event, "submitter_id": data.get("id")},
        )
        db.commit()
        return "sem_vinculo_ad"

    at = _parse_dt(data.get("completed_at") or data.get("declined_at"))
    decision = "ACEITO" if event == "form.completed" else "RECUSADO"
    tz = ZoneInfo(settings.timezone)
    files: dict[str, bytes] = {}  # chave -> conteúdo (gravados só no final)

    trail_key = trail_sha = None
    audit_url = data.get("audit_log_url") or (data.get("submission") or {}).get("audit_log_url")
    if audit_url:
        trail = client.download(audit_url)
        trail_sha = sha256_hex(trail)
        trail_key = f"documentos/{doc.id}/docuseal-trilha-{trail_sha[:16]}.pdf"
        files[trail_key] = trail

    # Todos os documentos do envio (um modelo pode ter vários PDFs): cada um
    # recebe o selo final da empresa. O primeiro é o "documento principal".
    sealed_docs: list[dict] = []
    if decision == "ACEITO":
        documents = data.get("documents") or []
        if not documents:
            raise DocusealError("webhook sem documentos")
        for i, item in enumerate(documents):
            signed = client.download(str(item.get("url") or ""))
            signed_sha = sha256_hex(signed)
            try:
                final = sealer.seal_final(
                    signed,
                    reason=f"Selo da empresa sobre documento assinado no DocuSeal ({doc.id})",
                )
            except SealingError as exc:
                raise DocusealError(str(exc)) from exc
            final_sha = sha256_hex(final)
            suffix = "" if i == 0 else f"-{i + 1}"
            signed_key = f"documentos/{doc.id}/docuseal-assinado{suffix}-{signed_sha[:16]}.pdf"
            final_key = f"documentos/{doc.id}/final{suffix}-{final_sha[:16]}.pdf"
            files[signed_key] = signed
            files[final_key] = final
            entry: dict = {
                "nome": str(item.get("name") or f"documento-{i + 1}")[:200],
                "sha256_assinado_docuseal": signed_sha,
                "key_assinado_docuseal": signed_key,
                "sha256": final_sha,
                "key": final_key,
                "_final": final,
            }
            sealed_docs.append(entry)
    main = sealed_docs[0] if sealed_docs else None
    extras = [{k: v for k, v in e.items() if k != "_final"} for e in sealed_docs[1:]]

    ctx = opened.data or {}
    confirmation = ctx.get("confirmacao") or "sessao_ad"
    if decision == "ACEITO":
        declaration = doc.declaration_text or doc.document_type.declaration_text
    else:
        declaration = DECLINE_DECLARATION
    evidence = {
        "versao": 2,
        "tipo": "manifestacao_eletronica_docuseal",
        "decisao": decision,
        "natureza": doc.document_type.manifestation_kind,
        "declaracao": {"texto": declaration, "sha256": sha256_hex(declaration)},
        "motivo": data.get("decline_reason") if decision == "RECUSADO" else None,
        "documento": {
            "id": doc.id,
            "titulo": doc.titulo,
            "codigo_verificacao": doc.verification_code,
            "sha256_assinado_docuseal": main["sha256_assinado_docuseal"] if main else None,
            "sha256_final": main["sha256"] if main else None,
            "arquivos_adicionais": extras,
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
        "autenticacao": {
            "login": "Active Directory (LDAPS bind)",
            "confirmacao_ao_abrir_link": confirmation,
            "link": "uso único, criado na sessão autenticada, sem envio por e-mail",
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
            "recusado_em": data.get("declined_at"),
            "trilha_key": trail_key,
            "trilha_sha256": trail_sha,
        },
        "tempo": {
            "data_hora_utc": audit.iso_utc(at),
            "data_hora_local": at.astimezone(tz).strftime("%Y-%m-%dT%H:%M:%S%z"),
            "fuso": settings.timezone,
            "fonte_de_tempo": "data/hora informada pelo DocuSeal no webhook (servidor próprio)",
        },
    }
    evidence_json = canonical_json(evidence)
    evidence_sha = sha256_hex(evidence_json)

    opened_at = opened.occurred_at
    if opened_at.tzinfo is None:
        opened_at = opened_at.replace(tzinfo=UTC)
    rows = [
        ("Documento", f"{doc.titulo} ({doc.document_type.nome})"),
        ("Código de verificação", doc.verification_code),
        ("Decisão", "ASSINADO" if decision == "ACEITO" else "RECUSA REGISTRADA"),
        ("SHA-256 do documento final", main["sha256"] if main else "—"),
    ]
    for e in extras:
        rows.append((f"SHA-256 de {e['nome']}", e["sha256"]))
    rows += [
        ("Colaborador", f"{doc.employee.nome} — matrícula {doc.employee.matricula}"),
        ("Usuário AD", f"{opened.actor_ref} ({ctx.get('upn') or '—'})"),
        ("objectGUID (AD)", ctx.get("objectGUID") or "—"),
        (
            "Link aberto no portal",
            f"{opened_at.astimezone(tz):%d/%m/%Y %H:%M:%S} · IP {opened.ip} · {confirmation}",
        ),
        (
            "Concluído no DocuSeal" if decision == "ACEITO" else "Recusado no DocuSeal",
            f"{at.astimezone(tz):%d/%m/%Y %H:%M:%S} ({settings.timezone})",
        ),
        ("Trilha DocuSeal (SHA-256)", trail_sha or "—"),
    ]
    if decision == "RECUSADO" and data.get("decline_reason"):
        rows.append(("Motivo informado", str(data.get("decline_reason"))[:2000]))
    try:
        receipt = build_receipt_pdf(
            ReceiptData(
                company_name=settings.company_name,
                company_cnpj=settings.company_cnpj,
                title="Comprovante de Assinatura Eletrônica"
                if decision == "ACEITO"
                else "Comprovante de Recusa de Assinatura",
                rows=rows,
                declaration=declaration,
                declaration_label="Declaração aceita pelo colaborador"
                if decision == "ACEITO"
                else "Registro de recusa",
                evidence_sha256=evidence_sha,
                verification_url=f"{settings.base_url.rstrip('/')}/verificar/{doc.verification_code}",
                legal_note=LEGAL_NOTE_DOCUSEAL,
            ),
            evidence_json,
            document_pdf=main["_final"] if main else None,
        )
        receipt = sealer.seal_receipt(receipt)
    except SealingError as exc:
        raise DocusealError(f"falha ao selar o comprovante: {exc}") from exc
    receipt_sha = sha256_hex(receipt)
    receipt_key = f"documentos/{doc.id}/comprovante-{receipt_sha[:16]}.pdf"
    files[receipt_key] = receipt

    # Grava os arquivos só depois de tudo gerado (falha antes disso = nada gravado).
    for key, content in files.items():
        _put(storage, key, content)

    if main:
        doc.original_key, doc.original_sha256 = (
            main["key_assinado_docuseal"],
            main["sha256_assinado_docuseal"],
        )
        doc.final_key, doc.final_sha256 = main["key"], main["sha256"]
    doc.receipt_key, doc.receipt_sha256 = receipt_key, receipt_sha
    db.add(
        Acceptance(
            document_id=doc.id,
            employee_id=doc.employee_id,
            decision=decision,
            reason=str(data.get("decline_reason") or "")[:2000] or None,
            source="docuseal",
            ad_object_guid=ctx.get("objectGUID") or "",
            ad_username=opened.actor_ref,
            ad_upn=ctx.get("upn"),
            ip=str(opened.ip or data.get("ip") or "")[:45],
            user_agent=str(opened.user_agent or data.get("ua") or "")[:512],
            accepted_at=at,
            reauth_method=f"{confirmation}+link_docuseal"[:32],
            session_ref=ctx.get("sessao_ref") or "",
            document_sha256=doc.final_sha256 or "",
            declaration_text=declaration,
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
            "sha256_adicionais": [e["sha256"] for e in extras],
            "sha256_comprovante": doc.receipt_sha256,
            "evidencia_sha256": evidence_sha,
            "ip_docuseal": data.get("ip"),
        },
    )
    db.commit()
    return "processado"
