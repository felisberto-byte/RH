from __future__ import annotations

import logging
from pathlib import Path

from fastapi import FastAPI, HTTPException, Request
from fastapi.responses import RedirectResponse
from fastapi.staticfiles import StaticFiles
from fastapi.templating import Jinja2Templates
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
)
from portal.web.deps import AppContext, LoginRequired, render
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
        return RedirectResponse("/login", status_code=303)

    @app.exception_handler(StarletteHTTPException)
    async def _http_error(request: Request, exc: HTTPException):
        if request.url.path.startswith("/webhooks/") or "text/html" not in request.headers.get(
            "accept", ""
        ):
            from fastapi.responses import JSONResponse

            return JSONResponse({"detail": exc.detail}, status_code=exc.status_code)
        return render(
            request, "erro.html", status_code=exc.status_code, user=None, message=exc.detail or "Erro"
        )

    return app
