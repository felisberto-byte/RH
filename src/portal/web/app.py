from __future__ import annotations

import logging
import secrets
from http import HTTPStatus
from pathlib import Path

from fastapi import FastAPI, Request
from fastapi.exceptions import RequestValidationError
from fastapi.responses import JSONResponse, RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
from starlette.concurrency import run_in_threadpool
from starlette.exceptions import HTTPException as StarletteHTTPException

from portal import __version__
from portal.auth import build_provider
from portal.auth.base import AuthProvider
from portal.config import Settings, get_settings
from portal.db import Database
from portal.integrations.docuseal import DocusealClient
from portal.signing.pades import Sealer
from portal.storage import Storage, build_storage
from portal.web import (
    routes_account,
    routes_admin,
    routes_employee,
    routes_public,
    routes_webhooks,
    security,
)
from portal.web.deps import AppContext, LoginRequired, peek_user, render
from portal.web.security import SecurityHeadersMiddleware

HERE = Path(__file__).parent
log = logging.getLogger(__name__)


def build_sealer(s: Settings) -> Sealer | None:
    if not s.signing_pfx_file:
        log.warning("PORTAL_SIGNING_PFX_FILE não configurado: emissão/aceite desabilitados")
        return None
    tsa_auth = (s.tsa_username, s.tsa_password.get_secret_value()) if s.tsa_username else None
    return Sealer(
        s.signing_pfx_file,
        s.signing_pfx_password.get_secret_value(),
        ca_chain_files=s.signing_ca_chain_files,
        location=s.signing_location,
        tsa_url=s.tsa_url,
        tsa_auth=tsa_auth,
        policy_oid=s.signature_policy_oid,
        policy_hash_b64=s.signature_policy_hash_b64,
        policy_hash_alg=s.signature_policy_hash_alg,
        policy_uri=s.signature_policy_uri,
        ltv_trust_roots=s.signing_trust_root_files if s.signing_ltv else None,
    )


def create_app(
    settings: Settings | None = None,
    *,
    auth: AuthProvider | None = None,
    sealer: Sealer | None = None,
    storage: Storage | None = None,
    docuseal: DocusealClient | None = None,
    database: Database | None = None,
) -> FastAPI:
    s = settings or get_settings()
    docs_enabled = s.env != "prod"
    app = FastAPI(
        title="Portal do Colaborador",
        version=__version__,
        docs_url="/docs" if docs_enabled else None,
        redoc_url=None,
        openapi_url="/openapi.json" if docs_enabled else None,
    )
    templates = Jinja2Templates(directory=str(HERE / "templates"))
    if docuseal is None and s.docuseal_enabled:
        docuseal = DocusealClient(s.docuseal_url, s.docuseal_api_token.get_secret_value())
    app.state.ctx = AppContext(
        settings=s,
        database=database or Database(s.database_url),
        storage=storage or build_storage(s),
        sealer=sealer if sealer is not None else build_sealer(s),
        auth=auth or build_provider(s),
        templates=templates,
        docuseal=docuseal,
    )
    app.add_middleware(SecurityHeadersMiddleware, settings=s)
    app.mount("/static", StaticFiles(directory=str(HERE / "static")), name="static")
    for r in (routes_public, routes_account, routes_employee, routes_admin, routes_webhooks):
        app.include_router(r.router)

    @app.exception_handler(LoginRequired)
    async def _login_required(request: Request, _exc: LoginRequired):
        had_session = bool(request.cookies.get(security.cookie_name(s)))
        return RedirectResponse("/login?msg=expirou" if had_session else "/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: StarletteHTTPException):
        message = exc.detail
        if not isinstance(message, str) or message == _default_phrase(exc.status_code):
            message = HTTP_MESSAGES.get(exc.status_code, "Não foi possível concluir a solicitação.")
        return await _error_response(request, exc.status_code, message)

    @app.exception_handler(RequestValidationError)
    async def _validation_error(request: Request, exc: RequestValidationError):
        log.info("requisição inválida em %s: %s campo(s)", request.url.path, len(exc.errors()))
        return await _error_response(
            request, 400, "Dados do formulário inválidos ou incompletos. Volte e tente novamente."
        )

    @app.exception_handler(Exception)
    async def _unexpected(request: Request, exc: Exception):
        ref = secrets.token_hex(6)
        log.exception("erro inesperado ref=%s %s %s", ref, request.method, request.url.path)
        return await _error_response(
            request,
            500,
            "Ocorreu um erro inesperado e nada foi registrado. Tente novamente em instantes; "
            f"se persistir, informe ao suporte o código {ref}.",
        )

    return app


HTTP_MESSAGES = {
    400: "Solicitação inválida.",
    401: "Acesso não autorizado.",
    403: "Acesso negado.",
    404: "Página não encontrada.",
    405: "Ação inválida para esta página.",
    413: "Arquivo grande demais.",
    429: "Muitas solicitações. Aguarde alguns instantes.",
    500: "Erro interno.",
    502: "Serviço externo indisponível no momento.",
    503: "Serviço temporariamente indisponível.",
}


def _default_phrase(code: int) -> str:
    try:
        return HTTPStatus(code).phrase
    except ValueError:
        return ""


def _wants_html(request: Request) -> bool:
    return not request.url.path.startswith("/webhooks/") and "text/html" in request.headers.get(
        "accept", ""
    )


async def _error_response(request: Request, status_code: int, message: str):
    if not _wants_html(request):
        return JSONResponse({"detail": message}, status_code=status_code)
    user = await run_in_threadpool(peek_user, request)
    return render(request, "erro.html", status_code=status_code, user=user, message=message)
