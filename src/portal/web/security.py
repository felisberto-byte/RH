"""Sessões no servidor, CSRF, IP do cliente e cabeçalhos de segurança."""

from __future__ import annotations

import hashlib
import hmac
import ipaddress
import secrets
from datetime import UTC, datetime, timedelta

from fastapi import Request
from sqlalchemy import func, select
from sqlalchemy.orm import Session
from starlette.middleware.base import BaseHTTPMiddleware

from portal.auth.base import Identity
from portal.config import Settings
from portal.db import utcnow
from portal.models import LoginAttempt, UserSession

LOGIN_CSRF_COOKIE = "portal_login_csrf"
VERIFY_CSRF_COOKIE = "portal_verify_csrf"


def cookie_name(settings: Settings) -> str:
    # Prefixo __Host- exige Secure, Path=/ e ausência de Domain (anti-subdomínio).
    return "__Host-portal" if settings.secure_cookies else "portal_session"


def token_hash(token: str) -> str:
    return hashlib.sha256(token.encode()).hexdigest()


def _aware(dt: datetime) -> datetime:
    return dt if dt.tzinfo else dt.replace(tzinfo=UTC)


def client_ip(request: Request, trusted_hops: int) -> str:
    """IP do cliente considerando ``trusted_hops`` proxies confiáveis à frente.

    Cada proxy confiável acrescenta o IP de quem o chamou ao final do
    X-Forwarded-For; valores à esquerda podem ser forjados pelo cliente.
    """
    peer = request.client.host if request.client else "0.0.0.0"  # noqa: S104
    if trusted_hops <= 0:
        return peer
    parts = [p.strip() for p in request.headers.get("x-forwarded-for", "").split(",") if p.strip()]
    if len(parts) < trusted_hops:
        return peer
    candidate = parts[-trusted_hops]
    try:
        return str(ipaddress.ip_address(candidate))
    except ValueError:
        return peer


def user_agent(request: Request) -> str:
    return request.headers.get("user-agent", "")[:512]


def create_session(
    db: Session, identity: Identity, employee_id: int | None, ip: str, ua: str
) -> tuple[str, UserSession]:
    token = secrets.token_urlsafe(32)
    sess = UserSession(
        token_hash=token_hash(token),
        employee_id=employee_id,
        username=identity.username,
        display_name=identity.display_name,
        object_guid=identity.object_guid,
        upn=identity.upn,
        dn=identity.dn,
        is_admin=identity.is_admin,
        csrf_token=secrets.token_urlsafe(32),
        ip=ip,
        user_agent=ua,
    )
    db.add(sess)
    return token, sess


def load_session(db: Session, token: str | None, settings: Settings) -> UserSession | None:
    if not token or len(token) > 128:
        return None
    sess = db.get(UserSession, token_hash(token))
    if sess is None or sess.revoked:
        return None
    now = utcnow()
    if now - _aware(sess.last_seen_at) > timedelta(minutes=settings.session_idle_minutes):
        return None
    if now - _aware(sess.created_at) > timedelta(hours=settings.session_absolute_hours):
        return None
    if now - _aware(sess.last_seen_at) > timedelta(seconds=60):
        sess.last_seen_at = now
        db.commit()
    return sess


def identity_from_session(sess: UserSession) -> Identity:
    return Identity(
        username=sess.username,
        display_name=sess.display_name,
        object_guid=sess.object_guid,
        dn=sess.dn,
        upn=sess.upn,
        is_admin=sess.is_admin,
    )


def csrf_ok(expected: str | None, received: str | None) -> bool:
    return bool(expected and received) and hmac.compare_digest(str(expected), str(received))


def too_many_failures(db: Session, settings: Settings, *, username: str, ip: str) -> bool:
    since = utcnow() - timedelta(minutes=settings.login_lockout_minutes)
    by_user = (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == username.lower(),
                LoginAttempt.success.is_(False),
                LoginAttempt.at >= since,
            )
        )
        or 0
    )
    by_ip = (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.ip == ip, LoginAttempt.success.is_(False), LoginAttempt.at >= since
            )
        )
        or 0
    )
    return by_user >= settings.login_max_failures or by_ip >= settings.login_max_failures * 4


CSP = (
    "default-src 'self'; img-src 'self' data:; style-src 'self'; script-src 'self'; "
    "object-src 'self'; frame-src 'self'; frame-ancestors 'self'; base-uri 'none'; "
    "form-action 'self'"
)


class SecurityHeadersMiddleware(BaseHTTPMiddleware):
    def __init__(self, app, settings: Settings):
        super().__init__(app)
        self.settings = settings

    async def dispatch(self, request, call_next):
        response = await call_next(request)
        h = response.headers
        h.setdefault("Content-Security-Policy", CSP)
        h.setdefault("X-Content-Type-Options", "nosniff")
        h.setdefault("X-Frame-Options", "SAMEORIGIN")
        h.setdefault("Referrer-Policy", "same-origin")
        h.setdefault("Permissions-Policy", "camera=(), microphone=(), geolocation=()")
        if not request.url.path.startswith("/static/"):
            h.setdefault("Cache-Control", "no-store")
        if self.settings.secure_cookies:
            h.setdefault("Strict-Transport-Security", "max-age=31536000; includeSubDomains")
        return response
