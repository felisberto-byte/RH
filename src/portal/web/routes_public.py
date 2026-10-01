from __future__ import annotations

import secrets

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import RedirectResponse
from sqlalchemy.orm import Session
from starlette.concurrency import run_in_threadpool

from portal import audit
from portal.audit import sha256_hex
from portal.auth.base import AuthError, DirectoryUnavailable
from portal.models import DocStatus, LoginAttempt
from portal.signing.pades import inspect_signatures, load_cert_files
from portal.web import security
from portal.web.deps import (
    CurrentUser,
    app_ctx,
    current_user,
    document_service,
    find_employee_for,
    get_db,
    render,
    require_csrf,
)

router = APIRouter()


def _login_page(request: Request, error: str | None = None, status_code: int = 200):
    token = secrets.token_urlsafe(24)
    resp = render(request, "login.html", status_code=status_code, error=error, login_csrf=token)
    resp.set_cookie(
        security.LOGIN_CSRF_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=app_ctx(request).settings.secure_cookies,
        max_age=1800,
    )
    return resp


@router.get("/")
def home(request: Request):
    return RedirectResponse("/documentos", status_code=303)


@router.get("/healthz")
def healthz():
    return {"status": "ok"}


@router.get("/login")
def login_form(request: Request):
    return _login_page(request)


@router.post("/login")
def login(
    request: Request,
    username: str = Form(""),
    password: str = Form(""),
    login_csrf: str = Form(""),
    db: Session = Depends(get_db),
):
    ctx = app_ctx(request)
    s = ctx.settings
    if not security.csrf_ok(request.cookies.get(security.LOGIN_CSRF_COOKIE), login_csrf):
        return _login_page(request, "Formulário expirado. Tente novamente.", 400)
    ip = security.client_ip(request, s.trusted_proxy_hops)
    ua = security.user_agent(request)
    uname = username.strip().lower()[:128]
    if not uname or not password:
        return _login_page(request, "Informe usuário e senha.", 400)
    if security.too_many_failures(db, s, username=uname, ip=ip):
        return _login_page(request, "Muitas tentativas. Aguarde alguns minutos.", 429)
    try:
        identity = ctx.auth.authenticate(username, password)
    except DirectoryUnavailable as exc:
        return _login_page(request, str(exc), 503)
    except AuthError as exc:
        db.add(LoginAttempt(username=uname, ip=ip, success=False))
        audit.record(
            db, action="LOGIN_FALHOU", actor_type="colaborador", actor_ref=uname, ip=ip, user_agent=ua
        )
        db.commit()
        return _login_page(request, str(exc), 401)

    employee = find_employee_for(db, identity)
    if employee is not None:
        if employee.ad_object_guid and employee.ad_object_guid != identity.object_guid:
            audit.record(
                db,
                action="VINCULO_AD_CONFLITO",
                actor_type="sistema",
                actor_ref=identity.username,
                ip=ip,
                data={"matricula": employee.matricula, "objectGUID": identity.object_guid},
            )
            db.commit()
            return _login_page(
                request, "Seu cadastro está vinculado a outro usuário. Procure o RH.", 403
            )
        if not employee.ativo:
            return _login_page(request, "Cadastro inativo. Procure o RH.", 403)
        if employee.ad_object_guid is None:
            employee.ad_object_guid = identity.object_guid
            employee.ad_username = identity.username
            audit.record(
                db,
                action="VINCULO_AD_CRIADO",
                actor_type="sistema",
                actor_ref=identity.username,
                ip=ip,
                data={"matricula": employee.matricula, "objectGUID": identity.object_guid},
            )
    elif not identity.is_admin:
        db.add(LoginAttempt(username=uname, ip=ip, success=False))
        db.commit()
        return _login_page(
            request,
            "Não encontramos seu cadastro de colaborador (matrícula no AD). Procure o RH.",
            403,
        )

    token, sess = security.create_session(db, identity, employee.id if employee else None, ip, ua)
    db.add(LoginAttempt(username=uname, ip=ip, success=True))
    audit.record(
        db,
        action="LOGIN",
        actor_type="rh" if identity.is_admin else "colaborador",
        actor_ref=identity.username,
        ip=ip,
        user_agent=ua,
        data={"objectGUID": identity.object_guid, "matricula": employee.matricula if employee else None},
    )
    db.commit()
    target = "/documentos" if employee else "/rh"
    resp = RedirectResponse(target, status_code=303)
    resp.set_cookie(
        security.cookie_name(s),
        token,
        httponly=True,
        secure=s.secure_cookies,
        samesite="lax",
        path="/",
    )
    resp.delete_cookie(security.LOGIN_CSRF_COOKIE)
    return resp


@router.post("/logout")
def logout(
    request: Request,
    user: CurrentUser = Depends(require_csrf),
    db: Session = Depends(get_db),
):
    s = app_ctx(request).settings
    user.session.revoked = True
    audit.record(
        db,
        action="LOGOUT",
        actor_type="colaborador",
        actor_ref=user.identity.username,
        ip=security.client_ip(request, s.trusted_proxy_hops),
    )
    db.commit()
    resp = RedirectResponse("/login?msg=saiu", status_code=303)
    resp.delete_cookie(security.cookie_name(s), path="/")
    return resp


# ------------------------------------------------------------ verificação
def _public_view(doc) -> dict:
    nome = doc.employee.nome.split()
    masked = f"{nome[0]} {nome[-1][0]}." if len(nome) > 1 else nome[0]
    return {
        "codigo": doc.verification_code,
        "tipo": doc.document_type.nome,
        "titulo": doc.titulo,
        "competencia": doc.competencia,
        "status": doc.status,
        "colaborador": masked,
        "emitido_em": doc.created_at,
        "concluido_em": doc.completed_at,
        "sha256_emitido": doc.sealed_sha256,
        "sha256_final": doc.final_sha256,
        "sha256_comprovante": doc.receipt_sha256,
    }


def _verify_allowed(request: Request, db: Session) -> bool:
    if app_ctx(request).settings.public_verification:
        return True
    try:
        current_user(request, db)
        return True
    except Exception:  # noqa: BLE001
        return False


@router.get("/verificar")
def verify_form(request: Request, db: Session = Depends(get_db)):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    token = secrets.token_urlsafe(24)
    resp = render(request, "verificar.html", result=None, login_csrf=token)
    resp.set_cookie(
        security.LOGIN_CSRF_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=app_ctx(request).settings.secure_cookies,
        max_age=1800,
    )
    return resp


@router.get("/verificar/{code}")
def verify_code(code: str, request: Request, db: Session = Depends(get_db)):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    doc = document_service(request, db).find_by_hash_or_code(code[:80])
    found = doc is not None and doc.status != DocStatus.CANCELADO
    return render(
        request,
        "verificar.html",
        result=_public_view(doc) if found else None,
        searched=True,
        login_csrf="",
        status_code=200 if found else 404,
    )


@router.post("/verificar")
async def verify_upload(
    request: Request,
    arquivo: UploadFile = File(...),
    login_csrf: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    if not security.csrf_ok(request.cookies.get(security.LOGIN_CSRF_COOKIE), login_csrf):
        return RedirectResponse("/verificar", status_code=303)
    data = await arquivo.read(25 * 1024 * 1024 + 1)
    if len(data) > 25 * 1024 * 1024:
        return RedirectResponse("/verificar", status_code=303)
    digest = sha256_hex(data)
    doc = document_service(request, db).find_by_hash_or_code(digest)
    found = doc is not None and doc.status != DocStatus.CANCELADO
    signatures = await run_in_threadpool(_signatures, request, data) if found else []
    return render(
        request,
        "verificar.html",
        result=_public_view(doc) if found else None,
        searched=True,
        uploaded_hash=digest,
        signatures=signatures,
        login_csrf="",
        status_code=200 if found else 404,
    )


def _signatures(request: Request, data: bytes) -> list[dict]:
    """Valida as assinaturas embutidas com as raízes configuradas (ICP-Brasil)."""
    s = app_ctx(request).settings
    roots_files = list(s.signing_trust_root_files) or list(s.signing_ca_chain_files)
    try:
        roots = load_cert_files(roots_files) if roots_files else []
        infos = inspect_signatures(data, roots)
    except Exception:  # noqa: BLE001 - PDF sem assinatura/ilegível: apenas não exibe
        return []
    return [
        {
            "campo": i.field,
            "titular": i.signer_subject,
            "integra": i.intact and i.valid,
            "confiavel": i.trusted,
            "docmdp_ok": i.docmdp_ok,
            "carimbo_tempo": i.timestamped,
            "alteracoes": i.modification_level,
        }
        for i in infos
    ]
