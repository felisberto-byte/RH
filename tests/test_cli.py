"""Comandos de operação: seed, verificação completa da auditoria e expurgo."""

from __future__ import annotations

from datetime import timedelta

import pytest
from sqlalchemy import create_engine, text

from portal import cli
from portal.config import get_settings
from portal.db import Database, utcnow
from portal.models import DocumentType, LoginAttempt


@pytest.fixture
def env(tmp_path, monkeypatch):
    url = f"sqlite:///{tmp_path}/cli.sqlite3"
    for k, v in {
        "PORTAL_ENV": "test",
        "PORTAL_DATABASE_URL": url,
        "PORTAL_STORAGE_LOCAL_PATH": str(tmp_path / "storage"),
        "PORTAL_AUTH_PROVIDER": "dev",
        "PORTAL_SECRET_KEY": "x" * 40,
        "PORTAL_LOG_FORMAT": "text",
    }.items():
        monkeypatch.setenv(k, v)
    get_settings.cache_clear()
    yield url
    get_settings.cache_clear()


def test_seed_verify_purge_and_tamper_detection(env, capsys):
    assert cli.main(["init-db"]) == 0
    assert cli.main(["seed"]) == 0
    db = Database(env)
    with db.sessionmaker() as s:
        kinds = {t.code: t.manifestation_kind for t in s.query(DocumentType)}
        assert kinds["HOLERITE"] == "ciencia" and kinds["CONTRATO"] == "aceite"
        old = utcnow() - timedelta(days=400)
        s.add(LoginAttempt(username="velho", ip="1.1.1.1", success=False, at=old))
        s.add(LoginAttempt(username="novo", ip="1.1.1.1", success=False))
        s.commit()

    assert cli.main(["purge", "--dias", "10"]) == 2  # mínimo de 30 dias
    assert cli.main(["purge", "--dias", "180"]) == 0
    with db.sessionmaker() as s:
        assert [a.username for a in s.query(LoginAttempt)] == ["novo"]

    assert cli.main(["verify-audit"]) == 0
    assert "auditoria íntegra" in capsys.readouterr().out

    # adulteração direta no banco (SQLite não tem os gatilhos do PostgreSQL)
    e = create_engine(env)
    with e.begin() as c:
        c.execute(text("UPDATE auditoria SET actor_ref = 'outro' WHERE id = 1"))
    e.dispose()
    assert cli.main(["verify-audit"]) == 1
    assert "CADEIA DE AUDITORIA COM FALHA" in capsys.readouterr().out
    db.engine.dispose()
