"""Termo de Adesão e configuração do segundo fator (TOTP) pelo colaborador."""

from __future__ import annotations

from zoneinfo import ZoneInfo

from fastapi import APIRouter, Depends, Form, HTTPException, Request
from fastapi.responses import RedirectResponse, Response
from sqlalchemy.exc import IntegrityError
from sqlalchemy.orm import Session

from portal import __version__, audit
from portal.audit import canonical_json, sha256_hex
from portal.auth.base import DirectoryUnavailable
from portal.db import utcnow
from portal.locks import account_lock, recent_failures
from portal.mfa import TotpService, qr_svg
from portal.models import AdhesionTerm, LoginAttempt
from portal.signing.pades import SealingError
from portal.signing.receipt import ReceiptData, build_receipt_pdf
from portal.terms import TermService
from portal.web import security
from portal.web.deps import (
    CurrentUser,
    app_ctx,
    current_user,
    get_db,
    render,
    require_csrf,
    safe_next,
)

router = APIRouter()


def _totp(request: Request, db: Session) -> TotpService:
    s = app_ctx(request).settings
    return TotpService(db, s.secret_key.get_secret_value(), s.totp_issuer)


def _check_password(
    request: Request, db: Session, user: CurrentUser, senha: str, purpose: str
) -> str | None:
    """Confirma a senha do AD com trava/limite por conta. Devolve mensagem de erro
    ou None. Faz commit (registra a tentativa e libera a trava)."""
    ctx = app_ctx(request)
    s = ctx.settings
    ip = security.client_ip(request, s.trusted_proxy_hops)
    key = user.identity.username.lower()
    account_lock(db, key)
    if recent_failures(db, key=key, minutes=s.login_lockout_minutes) >= s.login_max_failures:
        db.rollback()
        return "Muitas tentativas. Aguarde alguns minutos."
    try:
        ok = bool(senha) and ctx.auth.verify_password(user.identity, senha)
    except DirectoryUnavailable:
        db.rollback()
        return "Diretório indisponível no momento. Tente novamente em instantes."
    db.add(LoginAttempt(username=key, ip=ip, success=ok, purpose=purpose))
    db.commit()
    return None if ok else "Senha incorreta."


# ------------------------------------------------------------------ termo
@router.get("/termo")
def term_page(
    request: Request, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)
):
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    terms = TermService(db)
    term = terms.active()
    accepted = terms.acceptance_of(user.employee.id, term) if term else None
    return render(request, "termo.html", user=user, term=term, accepted=accepted, error=None)


def _term_receipt(request: Request, user: CurrentUser, term: AdhesionTerm, evidence_json: str) -> bytes:
    ctx = app_ctx(request)
    s = ctx.settings
    if ctx.sealer is None:
        raise SealingError("certificado de assinatura não configurado")
    assert user.employee is not None
    now = utcnow().astimezone(ZoneInfo(s.timezone))
    pdf = build_receipt_pdf(
        ReceiptData(
            company_name=s.company_name,
            company_cnpj=s.company_cnpj,
            title="Comprovante de Adesão ao Uso de Meios Eletrônicos",
            rows=[
                ("Termo", f"versão {term.version}"),
                ("SHA-256 do termo", term.sha256),
                ("Colaborador", f"{user.employee.nome} — matrícula {user.employee.matricula}"),
                ("Usuário AD", f"{user.identity.username} ({user.identity.upn or '—'})"),
                ("objectGUID (AD)", user.identity.object_guid),
                ("Data/hora", f"{now:%d/%m/%Y %H:%M:%S} ({s.timezone})"),
                ("Endereço IP", security.client_ip(request, s.trusted_proxy_hops)),
            ],
            declaration=term.text,
            declaration_label="Texto integral do termo aceito",
            evidence_sha256=sha256_hex(evidence_json),
            verification_url=f"{s.base_url.rstrip('/')}/termo",
            legal_note="Adesão registrada no Portal do Colaborador com confirmação de senha do AD.",
        ),
        evidence_json,
    )
    return ctx.sealer.seal_receipt(pdf, reason="Comprovante de adesão ao uso de meios eletrônicos")


@router.post("/termo")
def term_accept(
    request: Request,
    concordo: str = Form(""),
    senha: str = Form(""),
    termo_id: int = Form(0),
    termo_sha256: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    ctx = app_ctx(request)
    s = ctx.settings
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    terms = TermService(db)
    term = terms.active()
    if term is None or terms.acceptance_of(user.employee.id, term) is not None:
        return RedirectResponse("/documentos", status_code=303)

    def fail(msg: str, code: int = 400):
        return render(
            request, "termo.html", status_code=code, user=user, term=term, accepted=None, error=msg
        )

    # O colaborador aceita a versão que LEU: se o RH publicou outra no meio
    # tempo, mostra a nova em vez de registrar uma versão não vista.
    if termo_id != term.id or termo_sha256 != term.sha256:
        return fail("O termo foi atualizado. Leia a nova versão antes de aceitar.", 409)
    if concordo != "sim":
        return fail("Marque a caixa de concordância para continuar.")
    factors = "sessao_ad"
    if s.accept_reauth == "password":
        err = _check_password(request, db, user, senha, "termo")
        if err:
            return fail(err)
        factors = "senha_ad"
    ip = security.client_ip(request, s.trusted_proxy_hops)
    ua = security.user_agent(request)
    at = utcnow()
    evidence = {
        "versao": 1,
        "tipo": "adesao_meios_eletronicos",
        "termo": {"id": term.id, "versao": term.version, "sha256": term.sha256, "texto": term.text},
        "signatario": {
            "nome": user.employee.nome,
            "matricula": user.employee.matricula,
            "ad": {
                "sAMAccountName": user.identity.username,
                "userPrincipalName": user.identity.upn,
                "objectGUID": user.identity.object_guid,
                "dn": user.identity.dn,
            },
        },
        "autenticacao": {"login": "Active Directory (LDAPS bind)", "confirmacao_no_ato": factors},
        "contexto": {"ip": ip, "user_agent": ua},
        "data_hora_utc": audit.iso_utc(at),
        "sistema": {"portal_versao": __version__, "base_url": s.base_url},
    }
    evidence_json = canonical_json(evidence)
    try:
        receipt = _term_receipt(request, user, term, evidence_json)
    except SealingError:
        return fail("Não foi possível gerar o comprovante agora. Tente novamente em instantes.", 503)
    receipt_sha = sha256_hex(receipt)
    receipt_key = f"termos/{term.id}/{user.employee.id}-{receipt_sha[:16]}.pdf"
    try:
        ctx.storage.put(receipt_key, receipt)
        terms.register(
            user.employee,
            term,
            channel="portal",
            actor_type="colaborador",
            registered_by=user.identity.username,
            object_guid=user.identity.object_guid,
            ip=ip,
            user_agent=ua,
            evidence_json=evidence_json,
            receipt=(receipt_key, receipt_sha),
        )
        db.commit()
    except (IntegrityError, ValueError):  # duplo envio: já aceito
        db.rollback()
        return RedirectResponse("/documentos", status_code=303)
    if _needs_totp(request, db, user):
        return RedirectResponse("/mfa?next=/documentos", status_code=303)
    return RedirectResponse("/documentos", status_code=303)


@router.get("/termo/comprovante")
def term_receipt(
    request: Request, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)
):
    if user.employee is None:
        raise HTTPException(status_code=404, detail="Nenhum cadastro de colaborador vinculado.")
    terms = TermService(db)
    term = terms.active()
    acc = terms.acceptance_of(user.employee.id, term) if term else None
    if acc is None or not acc.receipt_key:
        raise HTTPException(status_code=404, detail="Comprovante não disponível para esta adesão.")
    data = app_ctx(request).storage.get(acc.receipt_key)
    if sha256_hex(data) != acc.receipt_sha256:
        raise HTTPException(status_code=500, detail="Falha de integridade do comprovante.")
    return Response(
        data,
        media_type="application/pdf",
        headers={"Content-Disposition": 'attachment; filename="comprovante-adesao.pdf"'},
    )


# ------------------------------------------------------------------ TOTP
def _needs_totp(request: Request, db: Session, user: CurrentUser) -> bool:
    s = app_ctx(request).settings
    if user.employee is None or s.accept_mfa != "totp":
        return False
    return not _totp(request, db).is_enrolled(user.employee.id)


@router.get("/mfa")
def mfa_page(
    request: Request,
    next: str = "",
    user: CurrentUser = Depends(current_user),
    db: Session = Depends(get_db),
):
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    totp = _totp(request, db)
    if totp.is_enrolled(user.employee.id):
        cred = totp.get(user.employee.id)
        return render(
            request,
            "mfa.html",
            user=user,
            enrolled=True,
            confirmed_at=cred.confirmed_at if cred else None,
            error=None,
            next=safe_next(next),
        )
    secret, uri = totp.pending_uri(user.employee) or totp.start_enrollment(user.employee)
    return render(
        request,
        "mfa.html",
        user=user,
        enrolled=False,
        secret=secret,
        qr=qr_svg(uri),
        error=None,
        next=safe_next(next),
    )


@router.post("/mfa")
def mfa_confirm(
    request: Request,
    codigo: str = Form(""),
    senha: str = Form(""),
    next: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    employee = user.employee
    s = app_ctx(request).settings
    totp = _totp(request, db)

    def fail(msg: str):
        pending = totp.pending_uri(employee)
        if pending is None:
            return RedirectResponse("/mfa", status_code=303)
        secret, uri = pending
        return render(
            request,
            "mfa.html",
            status_code=400,
            user=user,
            enrolled=False,
            secret=secret,
            qr=qr_svg(uri),
            error=msg,
            next=safe_next(next),
        )

    # Vincular um autenticador exige provar a senha do AD AGORA: uma sessão
    # aberta/esquecida não basta para cadastrar o celular de outra pessoa.
    err = _check_password(request, db, user, senha, "mfa")
    if err:
        return fail(err)
    ok = totp.confirm(
        employee,
        codigo,
        ip=security.client_ip(request, s.trusted_proxy_hops),
        ua=security.user_agent(request),
    )
    if not ok:
        return fail("Código inválido. Confira o relógio do celular e tente novamente.")
    target = safe_next(next) or "/documentos"
    sep = "&" if "?" in target else "?"
    return RedirectResponse(f"{target}{sep}msg=mfa", status_code=303)
