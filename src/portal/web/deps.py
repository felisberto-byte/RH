from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Form, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

from portal import audit
from portal.auth.base import AuthProvider, Identity
from portal.config import Settings
from portal.db import Database
from portal.documents.service import Actor, DocumentService, to_local
from portal.integrations.docuseal import DocusealClient
from portal.models import Employee, UserSession
from portal.signing.pades import Sealer
from portal.storage import Storage
from portal.web import security

MESSAGES = {
    "manifestado": "Registro efetuado com sucesso. O comprovante está disponível para download.",
    "recusado": "Divergência registrada. O RH verá sua contestação no painel de acompanhamento.",
    "saiu": "Você saiu do portal.",
    "expirou": "Sua sessão expirou. Entre novamente.",
    "cancelado": "Documento cancelado.",
    "importado": "Colaboradores importados.",
    "mfa": "Aplicativo autenticador configurado.",
    "termo": "Termo de adesão publicado.",
    "registrado": "Registro efetuado.",
}


@dataclass
class AppContext:
    settings: Settings
    database: Database
    storage: Storage
    sealer: Sealer | None
    auth: AuthProvider
    templates: Jinja2Templates
    docuseal: DocusealClient | None = None


class LoginRequired(Exception):
    pass


def app_ctx(request: Request) -> AppContext:
    return request.app.state.ctx


def get_db(request: Request) -> Iterator[Session]:
    yield from app_ctx(request).database.session()


@dataclass
class CurrentUser:
    session: UserSession
    identity: Identity
    employee: Employee | None

    @property
    def is_admin(self) -> bool:
        return self.session.is_admin


def _norm_matricula(value: str | None) -> str:
    if not value or not value.strip():
        return ""
    return value.strip().lstrip("0") or "0"


def link_problem(employee: Employee, identity: Identity) -> tuple[str, str] | None:
    """Confere o vínculo conta AD <-> cadastro. Retorna (evento, mensagem) se houver
    problema: outra conta já vinculada, ou matrícula do AD diferente do cadastro
    (conta renomeada/reutilizada)."""
    if employee.ad_object_guid and employee.ad_object_guid != identity.object_guid:
        return (
            "VINCULO_AD_CONFLITO",
            "Seu cadastro está vinculado a outro usuário. Procure o RH.",
        )
    if _norm_matricula(identity.employee_id) != _norm_matricula(employee.matricula):
        return (
            "VINCULO_AD_DIVERGENTE",
            "Sua conta do AD não corresponde ao cadastro vinculado. Procure o RH/TI.",
        )
    return None


def _revalidate(db: Session, ctx: AppContext, sess: UserSession) -> bool:
    """Revalida no AD (habilitada, grupos, vínculo) a cada N minutos. False = encerrar."""
    from datetime import timedelta

    from portal.auth.base import DirectoryUnavailable
    from portal.db import utcnow

    now = utcnow()
    if now - sess.validated_at < timedelta(minutes=ctx.settings.session_revalidate_minutes):
        return True
    identity = security.identity_from_session(sess)
    try:
        fresh = ctx.auth.refresh(identity)
    except DirectoryUnavailable:
        return True  # indisponibilidade não derruba sessões; tenta na próxima
    reason = None
    if fresh is None:
        reason = "conta desabilitada/fora do grupo no AD"
    elif sess.employee_id is not None:
        emp = db.get(Employee, sess.employee_id)
        if emp is None or not emp.ativo:
            reason = "cadastro inativo"
        elif link_problem(emp, fresh):
            reason = "vínculo AD divergente"
    if reason:
        sess.revoked = True
        audit.record(
            db,
            action="SESSAO_REVOGADA",
            actor_type="sistema",
            actor_ref=sess.username,
            data={"motivo": reason},
        )
        db.commit()
        return False
    assert fresh is not None
    sess.is_admin = fresh.is_admin
    sess.validated_at = now
    db.commit()
    return True


def current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    ctx = app_ctx(request)
    token = request.cookies.get(security.cookie_name(ctx.settings))
    sess = security.load_session(db, token, ctx.settings)
    if sess is None or not _revalidate(db, ctx, sess):
        raise LoginRequired()
    employee = db.get(Employee, sess.employee_id) if sess.employee_id else None
    if employee is not None and not employee.ativo:
        raise LoginRequired()
    return CurrentUser(sess, security.identity_from_session(sess), employee)


def require_admin(user: CurrentUser = Depends(current_user)) -> CurrentUser:
    if not user.is_admin:
        raise HTTPException(status_code=403, detail="Acesso restrito ao RH.")
    return user


def require_csrf(user: CurrentUser = Depends(current_user), csrf: str = Form("")) -> CurrentUser:
    if not security.csrf_ok(user.session.csrf_token, csrf):
        raise HTTPException(status_code=403, detail="Formulário expirado. Recarregue a página.")
    return user


def actor_for(request: Request, user: CurrentUser) -> Actor:
    s = app_ctx(request).settings
    port = request.headers.get(s.client_port_header, "")[:5] if s.client_port_header else ""
    return Actor(
        identity=user.identity,
        employee_id=user.employee.id if user.employee else None,
        # Referência derivada (não expõe a chave da sessão no banco/comprovante).
        session_ref=hashlib.sha256(f"sessao:{user.session.token_hash}".encode()).hexdigest(),
        ip=security.client_ip(request, s.trusted_proxy_hops),
        user_agent=security.user_agent(request),
        login_at=user.session.created_at,
        client_port=port if port.isdigit() else None,
    )


def document_service(request: Request, db: Session) -> DocumentService:
    ctx = app_ctx(request)
    return DocumentService(db, ctx.storage, ctx.settings, ctx.sealer, ctx.auth)


def find_employee_for(db: Session, identity: Identity) -> Employee | None:
    """Vincula o usuário do AD ao cadastro do colaborador.

    Prioridade: objectGUID já vinculado; senão matrícula (atributo employeeID),
    ignorando zeros à esquerda.
    """
    emp = db.scalar(select(Employee).where(Employee.ad_object_guid == identity.object_guid))
    if emp is not None:
        return emp
    if not identity.employee_id:
        return None
    key = identity.employee_id.strip().lstrip("0") or "0"
    return db.scalar(select(Employee).where(func.ltrim(Employee.matricula, "0") == key))


def safe_next(value: str | None) -> str:
    """Só aceita caminhos relativos do próprio portal (evita open redirect)."""
    v = (value or "").strip()
    if not v.startswith("/") or v.startswith("//") or "\\" in v or "\n" in v or "\r" in v:
        return ""
    return v[:200]


def render(request: Request, name: str, status_code: int = 200, **context: Any):
    ctx = app_ctx(request)
    msg = MESSAGES.get(request.query_params.get("msg", ""))
    base = {
        "request": request,
        "settings": ctx.settings,
        "flash": msg,
        "fmt_dt": lambda dt: to_local(dt, ctx.settings.timezone),
    }
    base.update(context)
    return ctx.templates.TemplateResponse(request, name, base, status_code=status_code)
