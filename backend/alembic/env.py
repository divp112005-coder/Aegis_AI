"""
Alembic migration environment — configured for Aegis AI.

Key design decisions:
  - DATABASE_URL is read from models.py (which itself reads from .env), so
    credentials are never duplicated in alembic.ini.
  - target_metadata points at Base.metadata for full autogenerate support.
  - compare_type=True means column *type* changes (e.g. String → Text) are
    also detected by autogenerate, not just added/removed columns.
  - include_schemas=False is the default; set True only if you use multiple
    PostgreSQL schemas.
"""

from logging.config import fileConfig

from sqlalchemy import engine_from_config, pool

from alembic import context

# ── Pull in application models ────────────────────────────────────────────────
# Import Base so Alembic can diff its metadata against the live DB schema.
# Import DATABASE_URL so we don't have to hardcode the connection string in
# alembic.ini (credentials stay in .env only).
from models import Base, DATABASE_URL  # noqa: E402

# ── Alembic Config object ─────────────────────────────────────────────────────
config = context.config

# Inject the real DB URL at runtime — overrides the blank sqlalchemy.url in
# alembic.ini.  This is the single source of truth for the connection string.
config.set_main_option("sqlalchemy.url", DATABASE_URL)

# Set up Python logging from the alembic.ini [loggers] section.
if config.config_file_name is not None:
    fileConfig(config.config_file_name)

# ── Metadata for autogenerate ─────────────────────────────────────────────────
# Alembic compares this metadata against the live DB to produce diffs.
target_metadata = Base.metadata


# ── Offline mode ──────────────────────────────────────────────────────────────
def run_migrations_offline() -> None:
    """Generate SQL migration scripts without connecting to the database.

    Useful for reviewing changes before applying them, or for generating
    scripts to hand off to a DBA.  Run with:
        alembic upgrade head --sql
    """
    url = config.get_main_option("sqlalchemy.url")
    context.configure(
        url=url,
        target_metadata=target_metadata,
        literal_binds=True,
        dialect_opts={"paramstyle": "named"},
        # Detect column type changes (e.g. String → Text) in offline mode too.
        compare_type=True,
    )

    with context.begin_transaction():
        context.run_migrations()


# ── Online mode ───────────────────────────────────────────────────────────────
def run_migrations_online() -> None:
    """Apply migrations directly against the live database.

    This is the normal operating mode used by:
        alembic upgrade head
        alembic downgrade -1
    """
    connectable = engine_from_config(
        config.get_section(config.config_ini_section, {}),
        prefix="sqlalchemy.",
        poolclass=pool.NullPool,
    )

    with connectable.connect() as connection:
        context.configure(
            connection=connection,
            target_metadata=target_metadata,
            # Detect column type changes (e.g. Integer → BigInteger).
            compare_type=True,
            # Detect server-side default changes too.
            compare_server_default=True,
        )

        with context.begin_transaction():
            context.run_migrations()


if context.is_offline_mode():
    run_migrations_offline()
else:
    run_migrations_online()
