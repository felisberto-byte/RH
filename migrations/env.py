"""Ambiente do Alembic: usa PORTAL_DATABASE_URL e os modelos do portal."""

import os
from logging.config import fileConfig

from alembic import context
from sqlalchemy import engine_from_config, pool

from portal import models  # noqa: F401  (registra as tabelas)
from portal.config import get_settings
from portal.db import Base, UTCDateTime

config = context.config
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# URL: a passada programaticamente (testes) ou PORTAL_DATABASE_URL (o job de
# migração só recebe a credencial do dono do esquema, não as demais
# configurações). O "%" de senhas URL-encoded seria lido como interpolação do
# configparser: escapar.
_url = (
    config.attributes.get("database_url")
    or os.environ.get("PORTAL_DATABASE_URL")
    or get_settings().database_url
)
config.set_main_option("sqlalchemy.url", _url.replace("%", "%%"))
target_metadata = Base.metadata


def render_item(type_, obj, autogen_context):
    """Renderiza tipos próprios como tipos SQLAlchemy puros (migração autônoma)."""
    if type_ == "type" and isinstance(obj, UTCDateTime):
        return "sa.DateTime(timezone=True)"
    return False


def run_migrations_offline() -> None:
    context.configure(
        url=config.get_main_option("sqlalchemy.url"),
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        render_as_batch=True,
        render_item=render_item,
    )
    with context.begin_transaction():
        context.run_migrations()


def run_migrations_online() -> None:
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )
    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            render_as_batch=True,
            render_item=render_item,
        )
        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
