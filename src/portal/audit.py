"""Trilha de auditoria encadeada por hash (tamper-evident).

Cada evento grava ``hash = SHA-256(prev_hash || JSON canônico do evento)``.
Alterar, inserir ou remover qualquer evento quebra a cadeia, o que
``verify_chain`` detecta. Para proteção adicional, exporte periodicamente o
último hash para um local imutável (bucket com retenção) ou carimbe-o numa
ACT (carimbo do tempo).
"""

from __future__ import annotations

import hashlib
import json
import logging
from dataclasses import dataclass
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.orm import Session

from portal.db import utcnow
from portal.models import AuditChainHead, AuditEvent

GENESIS = "0" * 64
log = logging.getLogger("portal.auditoria")


def canonical_json(obj: Any) -> str:
    return json.dumps(obj, sort_keys=True, separators=(",", ":"), ensure_ascii=False, default=str)


def sha256_hex(data: bytes | str) -> str:
    if isinstance(data, str):
        data = data.encode("utf-8")
    return hashlib.sha256(data).hexdigest()


def iso_utc(dt: datetime) -> str:
    """ISO-8601 em UTC, estável entre bancos (SQLite devolve datetime ingênuo)."""
    if dt.tzinfo is None:
        dt = dt.replace(tzinfo=UTC)
    return dt.astimezone(UTC).isoformat(timespec="microseconds")


def _event_payload(ev: AuditEvent) -> dict[str, Any]:
    return {
        "occurred_at": iso_utc(ev.occurred_at),
        "actor_type": ev.actor_type,
        "actor_ref": ev.actor_ref,
        "action": ev.action,
        "document_id": ev.document_id,
        "ip": ev.ip,
        "user_agent": ev.user_agent,
        "data": ev.data or {},
    }


def compute_hash(prev_hash: str, ev: AuditEvent) -> str:
    return sha256_hex(prev_hash + "\n" + canonical_json(_event_payload(ev)))


def record(
    db: Session,
    *,
    action: str,
    actor_type: str,
    actor_ref: str,
    document_id: str | None = None,
    ip: str | None = None,
    user_agent: str | None = None,
    data: dict[str, Any] | None = None,
) -> AuditEvent:
    """Acrescenta um evento à cadeia. Deve rodar dentro da transação do chamador."""
    head = db.execute(
        select(AuditChainHead).where(AuditChainHead.id == 1).with_for_update()
    ).scalar_one_or_none()
    if head is None:
        head = AuditChainHead(id=1, last_event_id=0, last_hash=GENESIS)
        db.add(head)
        db.flush()

    ev = AuditEvent(
        occurred_at=utcnow(),
        actor_type=actor_type,
        actor_ref=actor_ref,
        action=action,
        document_id=document_id,
        ip=ip,
        user_agent=(user_agent or "")[:512] or None,
        data=data or {},
        prev_hash=head.last_hash,
    )
    ev.hash = compute_hash(head.last_hash, ev)
    db.add(ev)
    db.flush()
    head.last_event_id = ev.id
    head.last_hash = ev.hash
    # Linha para métricas/alertas do Cloud Logging (sem dados pessoais além do id).
    log.info("auditoria %s evento=%s documento=%s", action, ev.id, document_id or "-")
    return ev


@dataclass
class ChainReport:
    ok: bool
    checked: int
    first_bad_id: int | None = None
    reason: str | None = None
    head_hash: str = GENESIS


def verify_chain(db: Session, batch_size: int = 1000) -> ChainReport:
    prev = GENESIS
    checked = 0
    last_id = 0
    while True:
        rows = db.scalars(
            select(AuditEvent).where(AuditEvent.id > last_id).order_by(AuditEvent.id).limit(batch_size)
        ).all()
        if not rows:
            break
        for ev in rows:
            if ev.prev_hash != prev:
                return ChainReport(False, checked, ev.id, "prev_hash não confere (evento removido?)")
            if compute_hash(prev, ev) != ev.hash:
                return ChainReport(False, checked, ev.id, "hash não confere (evento alterado)")
            prev = ev.hash
            checked += 1
            last_id = ev.id
    head = db.get(AuditChainHead, 1)
    if head is not None and head.last_hash != prev:
        return ChainReport(False, checked, None, "cabeça da cadeia não confere (eventos truncados)")
    return ChainReport(True, checked, head_hash=prev)
