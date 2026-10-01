from __future__ import annotations

import logging
import re
import secrets

from fastapi import APIRouter, Depends, File, Form, Request, UploadFile
from fastapi.responses import JSONResponse, RedirectResponse
from sqlalchemy import select, text
from sqlalchemy.orm import Session

from portal import audit
from portal.audit import sha256_hex
from portal.auth.base import AuthError, DirectoryUnavailable
from portal.locks import account_lock, canonical_account, recent_failures, recent_ip_login_failures
from portal.models import AuditEvent, DocStatus, Document, LoginAttempt
from portal.signing.pades import inspect_signatures, load_cert_files
from portal.web import security
from portal.web.deps import (
    CurrentUser,
    app_ctx,
    current_user,
    document_service,
    find_employee_for,
    get_db,
    link_problem,
    peek_user,
    render,
    require_csrf,
)

router = APIRouter()
log = logging.getLogger(__name__)


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
    """Vivacidade (processo responde). Não toca em dependências."""
    return {"status": "ok"}


@router.get("/readyz")
def readyz(request: Request, db: Session = Depends(get_db)):
    """Prontidão: banco acessível e certificado de selo dentro da validade."""
    ctx = app_ctx(request)
    problems = []
    try:
        db.execute(text("SELECT 1"))
    except Exception:  # noqa: BLE001
        log.exception("readyz: banco indisponível")
        problems.append("banco")
    if ctx.sealer is None:
        problems.append("certificado_nao_configurado")
    else:
        try:
            ctx.sealer.ensure_valid()
        except Exception:  # noqa: BLE001
            log.error("readyz: certificado de selo fora da validade")
            problems.append("certificado_fora_da_validade")
    if problems:
        return JSONResponse({"status": "indisponivel", "falhas": problems}, status_code=503)
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
    key = canonical_account(username)
    if not key or not password:
        return _login_page(request, "Informe usuário e senha.", 400)
    # Serializa por conta: checagem + bind + registro. Variações digitadas
    # (DOMINIO\x, x@dominio) compartilham o mesmo contador.
    account_lock(db, key)
    if recent_failures(db, key=key, minutes=s.login_lockout_minutes) >= s.login_max_failures or (
        recent_ip_login_failures(db, ip=ip, minutes=s.login_lockout_minutes)
        >= s.login_max_failures_per_ip
    ):
        db.rollback()
        return _login_page(request, "Muitas tentativas. Aguarde alguns minutos.", 429)
    try:
        identity = ctx.auth.authenticate(username, password)
    except DirectoryUnavailable as exc:
        db.rollback()
        return _login_page(request, str(exc), 503)
    except AuthError as exc:
        db.add(LoginAttempt(username=key, ip=ip, success=False, purpose="login"))
        audit.record(
            db, action="LOGIN_FALHOU", actor_type="colaborador", actor_ref=key, ip=ip, user_agent=ua
        )
        db.commit()
        return _login_page(request, str(exc), 401)

    employee = find_employee_for(db, identity)
    if employee is not None:
        problem = link_problem(employee, identity)
        if problem:
            audit.record(
                db,
                action=problem[0],
                actor_type="sistema",
                actor_ref=identity.username,
                ip=ip,
                data={
                    "matricula": employee.matricula,
                    "objectGUID": identity.object_guid,
                    "matricula_no_ad": identity.employee_id,
                },
            )
            db.commit()
            return _login_page(request, problem[1], 403)
        if not employee.ativo:
            db.rollback()
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
        db.add(LoginAttempt(username=key, ip=ip, success=False, purpose="login"))
        db.commit()
        return _login_page(
            request,
            "Não encontramos seu cadastro de colaborador (matrícula no AD). Procure o RH.",
            403,
        )

    token, sess = security.create_session(db, identity, employee.id if employee else None, ip, ua)
    db.add(LoginAttempt(username=key, ip=ip, success=True, purpose="login"))
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
    resp.delete_cookie(security.LOGIN_CSRF_COOKIE, secure=s.secure_cookies, samesite="strict")
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
    # __Host- exige Secure também na remoção, senão o navegador ignora.
    resp.delete_cookie(
        security.cookie_name(s), path="/", secure=s.secure_cookies, httponly=True, samesite="lax"
    )
    return resp


# ------------------------------------------------------------ verificação
MAX_VERIFY_BYTES = 25 * 1024 * 1024
_CODE_RE = re.compile(r"[A-Za-z0-9-]{4,80}")


def _public_view(db: Session, doc: Document) -> dict:
    nome = doc.employee.nome.split()
    masked = f"{nome[0]} {nome[-1][0]}." if len(nome) > 1 else nome[0]
    view = {
        "codigo": doc.verification_code,
        "tipo": doc.document_type.nome,
        "titulo": doc.titulo,
        "competencia": doc.competencia,
        "status": doc.status,
        "colaborador": masked,
        "emitido_em": doc.created_at,
        "concluido_em": doc.completed_at,
        "cancelado_em": None,
        "sha256_emitido": doc.sealed_sha256,
        "sha256_final": doc.final_sha256,
        "sha256_comprovante": doc.receipt_sha256,
    }
    if doc.status == DocStatus.CANCELADO:
        # Informa que o documento existiu e foi cancelado (sem o motivo, que é interno).
        view["cancelado_em"] = db.scalar(
            select(AuditEvent.occurred_at).where(
                AuditEvent.document_id == doc.id, AuditEvent.action == "DOCUMENTO_CANCELADO"
            )
        )
    return view


def _verify_allowed(request: Request, db: Session) -> bool:
    if app_ctx(request).settings.public_verification:
        return True
    try:
        current_user(request, db)
        return True
    except Exception:  # noqa: BLE001
        return False


def _verify_page(request: Request, status_code: int = 200, **context):
    """Sempre exibe os formulários (código e arquivo) com um token novo, em
    cookie próprio (não interfere no formulário de login aberto em outra aba)."""
    token = secrets.token_urlsafe(24)
    context.setdefault("result", None)
    context.setdefault("user", peek_user(request))  # só para o menu; não autoriza nada
    resp = render(request, "verificar.html", status_code=status_code, verify_csrf=token, **context)
    resp.set_cookie(
        security.VERIFY_CSRF_COOKIE,
        token,
        httponly=True,
        samesite="strict",
        secure=app_ctx(request).settings.secure_cookies,
        max_age=1800,
    )
    return resp


@router.get("/verificar")
def verify_form(request: Request, codigo: str = "", db: Session = Depends(get_db)):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    codigo = codigo.strip()
    if codigo:
        if not _CODE_RE.fullmatch(codigo):
            return _verify_page(request, 400, error="Código inválido. Confira e tente novamente.")
        return RedirectResponse(f"/verificar/{codigo.upper()}", status_code=303)
    return _verify_page(request)


@router.get("/verificar/{code}")
def verify_code(code: str, request: Request, db: Session = Depends(get_db)):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    doc = document_service(request, db).find_by_hash_or_code(code[:80])
    return _verify_page(
        request,
        200 if doc else 404,
        result=_public_view(db, doc) if doc else None,
        searched=True,
        searched_code=code[:80],
    )


@router.post("/verificar")
def verify_upload(
    request: Request,
    arquivo: UploadFile = File(...),
    verify_csrf: str = Form(""),
    db: Session = Depends(get_db),
):
    if not _verify_allowed(request, db):
        return RedirectResponse("/login", status_code=303)
    if not security.csrf_ok(request.cookies.get(security.VERIFY_CSRF_COOKIE), verify_csrf):
        return _verify_page(request, 400, error="Formulário expirado. Envie o arquivo novamente.")
    data = arquivo.file.read(MAX_VERIFY_BYTES + 1)
    if len(data) > MAX_VERIFY_BYTES:
        return _verify_page(request, 413, error="Arquivo maior que 25 MB.")
    if not data:
        return _verify_page(request, 400, error="Selecione um arquivo PDF.")
    digest = sha256_hex(data)
    doc = document_service(request, db).find_by_hash_or_code(digest)
    found = doc is not None and doc.status != DocStatus.CANCELADO
    return _verify_page(
        request,
        200 if doc else 404,
        result=_public_view(db, doc) if doc else None,
        searched=True,
        uploaded_hash=digest,
        signatures=_signatures(request, data) if found else [],
    )


def _signatures(request: Request, data: bytes) -> list[dict]:
    """Valida as assinaturas embutidas com as raízes configuradas (ICP-Brasil)."""
    s = app_ctx(request).settings
    roots_files = list(s.signing_trust_root_files) or list(s.signing_ca_chain_files)
    try:
        roots = load_cert_files(roots_files) if roots_files else []
        infos = inspect_signatures(data, roots)
    except Exception:  # noqa: BLE001 - PDF sem assinatura/ilegível: apenas não exibe
        log.info("verificação: assinaturas não puderam ser lidas", exc_info=True)
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
