from __future__ import annotations

import hashlib
from collections.abc import Iterator
from dataclasses import dataclass
from typing import Any

from fastapi import Depends, Form, HTTPException, Request
from fastapi.templating import Jinja2Templates
from sqlalchemy import func, select
from sqlalchemy.orm import Session

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
    "aceito": "Aceite registrado com sucesso. O comprovante está disponível para download.",
    "recusado": "Divergência registrada. O RH foi informado.",
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


def current_user(request: Request, db: Session = Depends(get_db)) -> CurrentUser:
    ctx = app_ctx(request)
    token = request.cookies.get(security.cookie_name(ctx.settings))
    sess = security.load_session(db, token, ctx.settings)
    if sess is None:
        raise LoginRequired()
    employee = db.get(Employee, sess.employee_id) if sess.employee_id else None
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
