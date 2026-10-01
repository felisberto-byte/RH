"""Travas e limitação de tentativas por conta.

As tentativas de senha precisam ser serializadas por conta: sem isso, várias
requisições paralelas passam todas pela checagem "menos de N falhas" e cada
uma faz um *bind* errado no AD, bloqueando a conta do colaborador no Windows.
"""

from __future__ import annotations

from datetime import timedelta

from sqlalchemy import func, select, text
from sqlalchemy.orm import Session

from portal.db import utcnow
from portal.models import LoginAttempt


def canonical_account(raw: str) -> str:
    """Chave canônica da conta: sem domínio (``DOM\\x`` / ``x@dom``) e minúscula.

    Variações digitadas do mesmo usuário compartilham o mesmo contador.
    """
    name = (raw or "").strip().lower()
    if "\\" in name:
        name = name.split("\\", 1)[1]
    if "@" in name:
        name = name.split("@", 1)[0]
    return name[:128]


def account_lock(db: Session, key: str) -> None:
    """Trava transacional por conta (PostgreSQL). Liberada no commit/rollback.

    No SQLite as escritas já são serializadas pelo próprio banco.
    """
    if db.get_bind().dialect.name == "postgresql":
        db.execute(text("SELECT pg_advisory_xact_lock(hashtext(:k))"), {"k": f"conta:{key}"})


def recent_failures(db: Session, *, key: str, minutes: int) -> int:
    since = utcnow() - timedelta(minutes=minutes)
    return (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.username == key,
                LoginAttempt.success.is_(False),
                LoginAttempt.at >= since,
            )
        )
        or 0
    )


def recent_ip_login_failures(db: Session, *, ip: str, minutes: int) -> int:
    """Falhas de LOGIN por IP (não conta confirmações de sessões já autenticadas)."""
    since = utcnow() - timedelta(minutes=minutes)
    return (
        db.scalar(
            select(func.count(LoginAttempt.id)).where(
                LoginAttempt.ip == ip,
                LoginAttempt.success.is_(False),
                LoginAttempt.purpose == "login",
                LoginAttempt.at >= since,
            )
        )
        or 0
    )
