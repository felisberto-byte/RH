from __future__ import annotations

import re
import unicodedata
from datetime import timedelta

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy import select
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.db import utcnow
from portal.documents.service import (
    KIND_LABELS,
    REFUSAL_DECLARATION,
    AdhesionRequired,
    DocumentError,
    DocumentService,
    IntegrityFailure,
    MfaEnrollmentRequired,
    NotFound,
)
from portal.integrations.docuseal import DocusealError
from portal.mfa import TotpService
from portal.models import DocStatus, Document, Engine
from portal.terms import TermService
from portal.web.deps import (
    CurrentUser,
    actor_for,
    app_ctx,
    current_user,
    document_service,
    get_db,
    render,
    require_csrf,
)

router = APIRouter(prefix="/documentos")

ARCHIVED = (DocStatus.ASSINADO, DocStatus.RECUSADO, DocStatus.DISPONIVEL)


def _filename(title: str, suffix: str = "") -> str:
    ascii_ = unicodedata.normalize("NFKD", title).encode("ascii", "ignore").decode()
    slug = re.sub(r"[^A-Za-z0-9]+", "-", ascii_).strip("-")[:80] or "documento"
    return f"{slug}{suffix}.pdf"


def _pdf(data: bytes, filename: str, download: bool = False) -> Response:
    disp = "attachment" if download else "inline"
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition": f'{disp}; filename="{filename}"'},
    )


def _employee_required(user: CurrentUser) -> int:
    if user.employee is None:
        raise HTTPException(status_code=404, detail="Nenhum cadastro de colaborador vinculado.")
    return user.employee.id


def _term_redirect(request: Request, db: Session, user: CurrentUser) -> RedirectResponse | None:
    if not app_ctx(request).settings.require_adhesion_term or user.employee is None:
        return None
    if TermService(db).pending_for(user.employee.id) is not None:
        return RedirectResponse("/termo", status_code=303)
    return None


def _mfa_missing(request: Request, db: Session, user: CurrentUser, doc: Document) -> bool:
    """True se a manifestação exigirá TOTP e o colaborador ainda não o configurou."""
    s = app_ctx(request).settings
    if user.employee is None:
        return False
    if not (s.accept_mfa == "totp" or doc.document_type.requires_totp):
        return False
    totp = TotpService(db, s.secret_key.get_secret_value(), s.totp_issuer)
    return not totp.is_enrolled(user.employee.id)


def _doc_context(request: Request, db: Session, user: CurrentUser, doc: Document, **extra):
    kind = doc.document_type.manifestation_kind
    declaration = DocumentService.declaration_for(doc)
    ctx = {
        "user": user,
        "doc": doc,
        "acceptance": doc.acceptance,
        "kind": kind,
        "kind_label": KIND_LABELS.get(kind, KIND_LABELS["aceite"])[2].lower(),
        "declaration": declaration,
        "declaration_sha256": sha256_hex(declaration),
        "refusal_declaration": REFUSAL_DECLARATION,
        "needs_totp": doc.document_type.requires_totp or app_ctx(request).settings.accept_mfa == "totp",
        "mfa_missing": _mfa_missing(request, db, user, doc),
        "has_file": bool(doc.final_key or doc.sealed_key),
        "error": None,
        "motivo": "",
        "refuse_open": False,
    }
    ctx.update(extra)
    return ctx


@router.get("")
def my_documents(
    request: Request,
    aba: str = "pendentes",
    user: CurrentUser = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.employee is None:
        return (
            RedirectResponse("/rh", status_code=303)
            if user.is_admin
            else render(
                request,
                "erro.html",
                status_code=404,
                user=user,
                message="Nenhum cadastro de colaborador vinculado ao seu usuário.",
            )
        )
    if (redirect := _term_redirect(request, db, user)) is not None:
        return redirect
    docs = document_service(request, db).list_for_employee(user.employee.id)
    pending = [d for d in docs if d.status == DocStatus.PENDENTE]
    # Documentos informativos ainda não abertos aparecem como "novos".
    new = [d for d in docs if d.status == DocStatus.DISPONIVEL and d.first_viewed_at is None]
    archived = [d for d in docs if d.status in ARCHIVED and d not in new]
    return render(
        request,
        "documentos.html",
        user=user,
        aba=aba,
        pending=pending,
        new=new,
        archived=archived,
    )


@router.get("/{doc_id}")
def document_detail(
    doc_id: str,
    request: Request,
    user: CurrentUser = Depends(current_user),
    db: Session = Depends(get_db),
):
    if (redirect := _term_redirect(request, db, user)) is not None:
        return redirect
    svc = document_service(request, db)
    try:
        doc = svc.get_for_employee(doc_id, _employee_required(user))
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    return render(request, "documento.html", **_doc_context(request, db, user, doc))


def _render_error(request, db, user, doc_id: str, message: str, status_code: int = 400, **extra):
    db.rollback()
    doc = document_service(request, db).get_for_employee(doc_id, _employee_required(user))
    return render(
        request,
        "documento.html",
        status_code=status_code,
        **_doc_context(request, db, user, doc, error=message, **extra),
    )


@router.get("/{doc_id}/pdf")
def document_pdf(
    doc_id: str,
    request: Request,
    download: bool = False,
    user: CurrentUser = Depends(current_user),
    db: Session = Depends(get_db),
):
    svc = document_service(request, db)
    try:
        doc = svc.get_for_employee(doc_id, _employee_required(user))
        data = svc.current_pdf(doc)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntegrityFailure as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    svc.mark_viewed(
        doc, actor_for(request, user), mode="download" if download else "inline", size=len(data)
    )
    return _pdf(data, _filename(doc.titulo), download)


@router.get("/{doc_id}/comprovante")
def document_receipt(
    doc_id: str,
    request: Request,
    user: CurrentUser = Depends(current_user),
    db: Session = Depends(get_db),
):
    svc = document_service(request, db)
    try:
        doc = svc.get_for_employee(doc_id, _employee_required(user))
        data = svc.receipt_pdf(doc)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except IntegrityFailure as exc:
        raise HTTPException(status_code=500, detail=str(exc)) from exc
    return _pdf(data, _filename(doc.titulo, "-comprovante"), download=True)


@router.post("/{doc_id}/aceite")
def accept(
    doc_id: str,
    request: Request,
    declaracao: str = Form(""),
    declaracao_sha256: str = Form(""),
    senha: str = Form(""),
    codigo: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    svc = document_service(request, db)
    try:
        svc.accept(
            doc_id,
            actor_for(request, user),
            declaration_confirmed=declaracao == "sim",
            declaration_sha256=declaracao_sha256 or None,
            password=senha,
            otp=codigo,
        )
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AdhesionRequired:
        db.rollback()
        return RedirectResponse("/termo", status_code=303)
    except MfaEnrollmentRequired:
        db.rollback()
        return RedirectResponse(f"/mfa?next=/documentos/{doc_id}", status_code=303)
    except DocumentError as exc:
        return _render_error(request, db, user, doc_id, str(exc))
    return RedirectResponse(f"/documentos/{doc_id}?msg=manifestado", status_code=303)


@router.post("/{doc_id}/recusa")
def refuse(
    doc_id: str,
    request: Request,
    motivo: str = Form(""),
    senha: str = Form(""),
    codigo: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    svc = document_service(request, db)
    try:
        svc.refuse(doc_id, actor_for(request, user), reason=motivo, password=senha, otp=codigo)
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    except AdhesionRequired:
        db.rollback()
        return RedirectResponse("/termo", status_code=303)
    except MfaEnrollmentRequired:
        db.rollback()
        return RedirectResponse(f"/mfa?next=/documentos/{doc_id}", status_code=303)
    except DocumentError as exc:
        # Preserva o texto digitado e reabre o painel de divergência.
        return _render_error(request, db, user, doc_id, str(exc), motivo=motivo[:2000], refuse_open=True)
    return RedirectResponse(f"/documentos/{doc_id}?msg=recusado", status_code=303)


@router.post("/{doc_id}/docuseal")
def open_docuseal(
    doc_id: str,
    request: Request,
    senha: str = Form(""),
    codigo: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    """Gera um link de assinatura DocuSeal de uso imediato, somente após a
    confirmação (senha/TOTP) do colaborador autenticado no AD."""
    ctx = app_ctx(request)
    svc = document_service(request, db)
    try:
        doc = svc.get_for_employee(doc_id, _employee_required(user))
    except NotFound as exc:
        raise HTTPException(status_code=404, detail=str(exc)) from exc
    if doc.engine != Engine.DOCUSEAL or doc.status != DocStatus.PENDENTE or ctx.docuseal is None:
        return _render_error(request, db, user, doc_id, "Assinatura via DocuSeal indisponível.")
    actor = actor_for(request, user)
    try:
        adhesion = svc.adhesion(doc.employee_id)
        factors = svc.step_up(actor, senha, codigo, require_totp=doc.document_type.requires_totp)
    except AdhesionRequired:
        db.rollback()
        return RedirectResponse("/termo", status_code=303)
    except MfaEnrollmentRequired:
        db.rollback()
        return RedirectResponse(f"/mfa?next=/documentos/{doc_id}", status_code=303)
    except DocumentError as exc:
        return _render_error(request, db, user, doc_id, str(exc))

    # Trava o documento: um duplo clique não pode criar dois envios ativos.
    doc = db.execute(
        select(Document)
        .where(Document.id == doc_id)
        .with_for_update()
        .execution_options(populate_existing=True)
    ).scalar_one()
    if doc.status != DocStatus.PENDENTE:
        return _render_error(request, db, user, doc_id, "Este documento não está mais pendente.")
    try:
        if doc.docuseal_submitter_id is not None:
            previous = ctx.docuseal.get_submitter(doc.docuseal_submitter_id)
            if previous and previous.get("completed_at"):
                return _render_error(
                    request,
                    db,
                    user,
                    doc_id,
                    "Sua assinatura já foi concluída e está sendo processada. Atualize em instantes.",
                )
            if doc.docuseal_submission_id is not None:
                ctx.docuseal.archive_submission(doc.docuseal_submission_id)
        emp = doc.employee
        link = ctx.docuseal.create_submission(
            template_id=doc.document_type.docuseal_template_id or 0,
            email=emp.email or f"{emp.matricula}@colaborador.invalid",
            name=emp.nome,
            external_id=doc.id,
            values={"Nome": emp.nome, "Matrícula": emp.matricula},
            metadata={
                "objectGUID": actor.identity.object_guid,
                "upn": actor.identity.upn or "",
                "sAMAccountName": actor.identity.username,
                "portal_documento": doc.id,
            },
            expire_at=utcnow() + timedelta(hours=2),
            completed_redirect_url=f"{ctx.settings.base_url.rstrip('/')}/documentos/{doc.id}",
        )
    except DocusealError as exc:
        return _render_error(request, db, user, doc_id, f"Falha ao abrir o DocuSeal: {exc}", 502)
    doc.docuseal_submission_id = link.submission_id
    doc.docuseal_submitter_id = link.submitter_id
    doc.docuseal_signing_url = link.signing_url
    if doc.first_viewed_at is None:
        doc.first_viewed_at = utcnow()
    audit.record(
        db,
        action="DOCUSEAL_LINK_ABERTO",
        actor_type="colaborador",
        actor_ref=actor.ref,
        document_id=doc.id,
        ip=actor.ip,
        user_agent=actor.user_agent,
        data={
            "objectGUID": actor.identity.object_guid,
            "upn": actor.identity.upn,
            "dn": actor.identity.dn,
            "sessao_ref": actor.session_ref,
            "confirmacao": factors,
            "termo_adesao": adhesion,
            "submitter_id": link.submitter_id,
            "submission_id": link.submission_id,
        },
    )
    db.commit()
    # Página intermediária com LINK (não redirecionamento do formulário): a CSP
    # form-action 'self' bloquearia o 303 para outro domínio no Chrome/Safari.
    return render(request, "docuseal_continuar.html", user=user, doc=doc, signing_url=link.signing_url)
