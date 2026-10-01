"""Migração Alembic no PostgreSQL real: esquema = modelos, gatilhos de
imutabilidade e privilégios mínimos do papel da aplicação."""

from __future__ import annotations

from pathlib import Path

import pytest
from alembic import command
from alembic.config import Config
from sqlalchemy import create_engine, text
from sqlalchemy.exc import DBAPIError

from portal.db import Base
from tests.conftest import TEST_DB_URL

ROOT = Path(__file__).resolve().parents[1]
ROLE = "portal_app_teste"

pytestmark = pytest.mark.skipif(
    not TEST_DB_URL.startswith("postgresql"), reason="requer PostgreSQL (PORTAL_TEST_DATABASE_URL)"
)


def _cfg() -> Config:
    cfg = Config(str(ROOT / "alembic.ini"))
    cfg.attributes["database_url"] = TEST_DB_URL
    cfg.cmd_opts = type("Opts", (), {"x": [f"app_role={ROLE}"]})()
    return cfg


def _blocked(engine, sql: str, expected: str, role: str | None = None) -> None:
    with pytest.raises(DBAPIError) as exc, engine.begin() as c:
        if role:
            c.execute(text(f"SET LOCAL ROLE {role}"))
        c.execute(text(sql))
    assert expected in str(exc.value), exc.value


def test_migration_matches_models_and_protects_evidence():
    engine = create_engine(TEST_DB_URL)
    with engine.begin() as c:
        Base.metadata.drop_all(c)
        c.execute(text("DROP TABLE IF EXISTS alembic_version"))
        c.execute(
            text(f"DO $$ BEGIN CREATE ROLE {ROLE}; EXCEPTION WHEN duplicate_object THEN NULL; END $$")
        )
    cfg = _cfg()
    try:
        command.upgrade(cfg, "head")
        command.check(cfg)  # esquema da migração == modelos

        with engine.begin() as c:
            assert c.execute(text("SELECT last_event_id FROM auditoria_cabeca")).scalar() == 0
            c.execute(
                text(
                    "INSERT INTO auditoria (occurred_at, actor_type, actor_ref, action, data, "
                    "prev_hash, hash) VALUES (now(), 'sistema', 't', 'TESTE', '{}', "
                    "repeat('0', 64), repeat('a', 64))"
                )
            )
            c.execute(
                text(
                    "INSERT INTO termos_adesao (version, text, sha256, active, published_by, "
                    "published_at) VALUES ('1', 'texto', repeat('b', 64), true, 'rh', now())"
                )
            )
        for sql in ("DELETE FROM auditoria", "UPDATE auditoria SET action = 'X'", "TRUNCATE auditoria"):
            _blocked(engine, sql, "append-only")
        _blocked(engine, "TRUNCATE aceites CASCADE", "append-only")
        _blocked(engine, "DELETE FROM auditoria_cabeca", "não pode ser apagada")
        _blocked(engine, "UPDATE auditoria_cabeca SET last_event_id = -1", "só pode avançar")
        _blocked(engine, "UPDATE termos_adesao SET text = 'outro'", "imutável")
        with engine.begin() as c:  # desativar o termo continua permitido
            c.execute(text("UPDATE termos_adesao SET active = false"))

        # papel da aplicação: inclui na trilha, mas não altera nem remove gatilhos
        with engine.begin() as c:
            c.execute(text(f"SET LOCAL ROLE {ROLE}"))
            c.execute(text("SELECT count(*) FROM documentos")).scalar()
            c.execute(text("DELETE FROM sessoes"))
            c.execute(
                text(
                    "INSERT INTO auditoria (occurred_at, actor_type, actor_ref, action, data, "
                    "prev_hash, hash) VALUES (now(), 'sistema', 't', 'APP', '{}', "
                    "repeat('a', 64), repeat('c', 64))"
                )
            )
        _blocked(engine, "DROP TRIGGER auditoria_append_only ON auditoria", "must be owner", ROLE)
        _blocked(engine, "DROP TABLE auditoria", "must be owner", ROLE)
        _blocked(engine, "UPDATE auditoria SET action = 'X'", "permission denied", ROLE)
    finally:
        command.downgrade(cfg, "base")
        with engine.begin() as c:
            c.execute(text("DROP TABLE IF EXISTS alembic_version"))
            c.execute(text(f"DROP OWNED BY {ROLE}"))
            c.execute(text(f"DROP ROLE IF EXISTS {ROLE}"))
        engine.dispose()


def test_db_app_role_command_creates_least_privilege_login(monkeypatch):
    from portal import cli

    role = "portal_app_cli_teste"
    monkeypatch.setenv("PORTAL_DATABASE_URL", TEST_DB_URL)
    monkeypatch.setenv("PORTAL_DB_APP_PASSWORD", "s3nha'com\"aspas-e-mais")
    engine = create_engine(TEST_DB_URL)
    try:
        assert cli.main(["db-app-role", "--papel", role]) == 0
        assert cli.main(["db-app-role", "--papel", role]) == 0  # idempotente (ALTER)
        with engine.begin() as c:
            row = c.execute(
                text("SELECT rolcanlogin, rolsuper, rolcreaterole FROM pg_roles WHERE rolname = :r"),
                {"r": role},
            ).one()
        assert tuple(row) == (True, False, False)
        assert cli.main(["db-app-role", "--papel", "x; DROP TABLE y"]) == 2
    finally:
        with engine.begin() as c:
            if c.execute(text("SELECT 1 FROM pg_roles WHERE rolname = :r"), {"r": role}).scalar():
                c.execute(text(f"DROP OWNED BY {role}"))
                c.execute(text(f"DROP ROLE {role}"))
        engine.dispose()
