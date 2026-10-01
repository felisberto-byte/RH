"""Termo de Adesão e configuração do segundo fator (TOTP) pelo colaborador."""

from __future__ import annotations

from fastapi import APIRouter, Depends, Form, Request
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session

from portal.mfa import TotpService, qr_svg
from portal.models import LoginAttempt
from portal.terms import TermService
from portal.web import security
from portal.web.deps import (
    CurrentUser,
    app_ctx,
    current_user,
    get_db,
    render,
    require_csrf,
)

router = APIRouter()


def _totp(request: Request, db: Session) -> TotpService:
    s = app_ctx(request).settings
    return TotpService(db, s.secret_key.get_secret_value(), s.totp_issuer)


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


@router.post("/termo")
def term_accept(
    request: Request,
    concordo: str = Form(""),
    senha: str = Form(""),
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

    def fail(msg: str):
        return render(
            request, "termo.html", status_code=400, user=user, term=term, accepted=None, error=msg
        )

    if concordo != "sim":
        return fail("Marque a caixa de concordância para continuar.")
    ip = security.client_ip(request, s.trusted_proxy_hops)
    uname = user.identity.username.lower()
    if security.too_many_failures(db, s, username=uname, ip=ip):
        return fail("Muitas tentativas. Aguarde alguns minutos.")
    if s.accept_reauth == "password":
        ok = bool(senha) and ctx.auth.verify_password(user.identity, senha)
        db.add(LoginAttempt(username=uname, ip=ip, success=ok, purpose="termo"))
        if not ok:
            db.commit()
            return fail("Senha incorreta.")
    terms.register(
        user.employee,
        term,
        channel="portal",
        registered_by=user.identity.username,
        object_guid=user.identity.object_guid,
        ip=ip,
        user_agent=security.user_agent(request),
    )
    db.commit()
    return RedirectResponse("/documentos", status_code=303)


@router.get("/mfa")
def mfa_page(request: Request, user: CurrentUser = Depends(current_user), db: Session = Depends(get_db)):
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    totp = _totp(request, db)
    if totp.is_enrolled(user.employee.id):
        return render(request, "mfa.html", user=user, enrolled=True, error=None)
    pending = totp.pending_uri(user.employee) or totp.start_enrollment(user.employee)
    secret, uri = pending
    return render(
        request, "mfa.html", user=user, enrolled=False, secret=secret, qr=qr_svg(uri), error=None
    )


@router.post("/mfa")
def mfa_confirm(
    request: Request,
    codigo: str = Form(""),
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    if user.employee is None:
        return RedirectResponse("/", status_code=303)
    s = app_ctx(request).settings
    totp = _totp(request, db)
    ok = totp.confirm(
        user.employee,
        codigo,
        ip=security.client_ip(request, s.trusted_proxy_hops),
        ua=security.user_agent(request),
    )
    if not ok:
        pending = totp.pending_uri(user.employee)
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
            error="Código inválido. Confira o relógio do celular e tente novamente.",
        )
    return RedirectResponse("/documentos?msg=mfa", status_code=303)
