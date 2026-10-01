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
from dataclasses import dataclass, field
from datetime import UTC, datetime
from typing import Any

from sqlalchemy import select
from sqlalchemy.dialects.postgresql import insert as pg_insert
from sqlalchemy.dialects.sqlite import insert as sqlite_insert
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


def _lock_head(db: Session) -> AuditChainHead:
    """Trava (FOR UPDATE) e RECARREGA a cabeça da cadeia.

    ``populate_existing`` é essencial: sem ele o SQLAlchemy devolve o objeto já
    presente no identity map (potencialmente desatualizado) mesmo após obter a
    trava, e dois escritores poderiam bifurcar a cadeia.
    """
    stmt = (
        select(AuditChainHead)
        .where(AuditChainHead.id == 1)
        .with_for_update()
        .execution_options(populate_existing=True)
    )
    head = db.execute(stmt).scalar_one_or_none()
    if head is None:  # banco criado sem a semente da migração
        ins = pg_insert if db.get_bind().dialect.name == "postgresql" else sqlite_insert
        db.execute(
            ins(AuditChainHead)
            .values(id=1, last_event_id=0, last_hash=GENESIS)
            .on_conflict_do_nothing(index_elements=["id"])
        )
        head = db.execute(stmt).scalar_one()
    return head


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
    """Acrescenta um evento à cadeia. Deve rodar dentro da transação do chamador
    e ser seguido de commit rápido (a cabeça fica travada até lá)."""
    head = _lock_head(db)

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
    head_event_id: int = 0
    start_after_id: int = 0
    anchors_checked: int = 0
    last_anchored_event_id: int | None = None
    anchor_problems: list[str] = field(default_factory=list)


def verify_chain(
    db: Session,
    batch_size: int = 1000,
    *,
    start_after_id: int = 0,
    start_hash: str = GENESIS,
) -> ChainReport:
    """Recalcula a cadeia de ``start_after_id`` até a cabeça lida NO INÍCIO
    (retrato consistente: eventos gravados durante a verificação ficam para a
    próxima). Com ``start_after_id`` > 0 a verificação é incremental a partir
    de um ponto já verificado (ex.: última âncora)."""
    head = db.execute(
        select(AuditChainHead).where(AuditChainHead.id == 1).execution_options(populate_existing=True)
    ).scalar_one_or_none()
    head_id = head.last_event_id if head else 0
    head_hash = head.last_hash if head else GENESIS
    prev = start_hash
    checked = 0
    last_id = start_after_id
    while last_id < head_id:
        rows = db.scalars(
            select(AuditEvent)
            .where(AuditEvent.id > last_id, AuditEvent.id <= head_id)
            .order_by(AuditEvent.id)
            .limit(batch_size)
        ).all()
        if not rows:
            break
        for ev in rows:
            if ev.prev_hash != prev:
                return ChainReport(
                    False,
                    checked,
                    ev.id,
                    "prev_hash não confere (evento removido?)",
                    start_after_id=start_after_id,
                )
            if compute_hash(prev, ev) != ev.hash:
                return ChainReport(
                    False,
                    checked,
                    ev.id,
                    "hash não confere (evento alterado)",
                    start_after_id=start_after_id,
                )
            prev = ev.hash
            checked += 1
            last_id = ev.id
    if head_id > start_after_id and prev != head_hash:
        return ChainReport(
            False,
            checked,
            None,
            "cabeça da cadeia não confere (eventos truncados)",
            start_after_id=start_after_id,
        )
    return ChainReport(
        True,
        checked,
        head_hash=prev if head_id else start_hash,
        head_event_id=head_id,
        start_after_id=start_after_id,
    )


def verify_anchors(db: Session, storage=None, trust_roots=None, report: ChainReport | None = None):
    """Confere cada âncora: o evento ancorado ainda tem o hash carimbado e, se
    ``storage`` for dado, o token RFC 3161 é íntegro e carimbou exatamente esse
    hash. Uma cadeia reescrita (mesmo "consistente") falha aqui."""
    from portal.anchoring import verify_anchor  # evita import circular
    from portal.models import AuditAnchor

    report = report or ChainReport(True, 0)
    for anchor in db.scalars(select(AuditAnchor).order_by(AuditAnchor.id)):
        ev = db.get(AuditEvent, anchor.head_event_id)
        if ev is None or ev.hash != anchor.head_hash:
            report.ok = False
            report.anchor_problems.append(
                f"âncora {anchor.id}: evento {anchor.head_event_id} não tem mais o hash carimbado"
            )
            continue
        if storage is not None:
            try:
                token = storage.get(anchor.token_key)
            except Exception as exc:  # noqa: BLE001
                report.ok = False
                report.anchor_problems.append(f"âncora {anchor.id}: token ilegível ({exc})")
                continue
            if sha256_hex(token) != anchor.token_sha256:
                report.ok = False
                report.anchor_problems.append(f"âncora {anchor.id}: token alterado")
                continue
            result = verify_anchor(anchor, token, trust_roots=trust_roots)
            if not (result["imprint_ok"] and result["intact"]):
                report.ok = False
                report.anchor_problems.append(f"âncora {anchor.id}: carimbo inválido {result}")
                continue
        report.anchors_checked += 1
        report.last_anchored_event_id = anchor.head_event_id
    return report
