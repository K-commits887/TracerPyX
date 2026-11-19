"""Database schema migration runner for TracerPyX."""

from __future__ import annotations

import sqlite3
from pathlib import Path
from typing import NamedTuple

from tracerpyx.core.exceptions import DatabaseMigrationError
from tracerpyx.core.logging import get_logger
from tracerpyx.db.connection import DatabaseManager

logger = get_logger("db.migrations")

_SCHEMA_SQL_PATH = Path(__file__).parent / "schema.sql"


class Migration(NamedTuple):
    version: int
    name: str
    sql: str


def get_available_migrations() -> list[Migration]:
    """Retrieve all defined migrations in order."""
    if not _SCHEMA_SQL_PATH.exists():
        raise DatabaseMigrationError(f"Schema definition file not found: {_SCHEMA_SQL_PATH}")

    # Migration 1: Initial schema
    v1_sql = _SCHEMA_SQL_PATH.read_text(encoding="utf-8")
    return [
        Migration(version=1, name="initial_schema", sql=v1_sql),
    ]


def get_applied_versions(conn: sqlite3.Connection) -> set[int]:
    """Query schema_migrations table for already-applied migration versions."""
    # Check if schema_migrations table exists
    cursor = conn.execute(
        "SELECT name FROM sqlite_master WHERE type='table' AND name='schema_migrations';"
    )
    if not cursor.fetchone():
        return set()

    rows = conn.execute("SELECT version FROM schema_migrations ORDER BY version ASC;").fetchall()
    return {row["version"] for row in rows}


def run_migrations(db: DatabaseManager) -> list[int]:
    """Apply all pending migrations to the database.

    Args:
        db: DatabaseManager instance.

    Returns:
        List of newly applied migration versions.
    """
    applied_now: list[int] = []
    migrations = get_available_migrations()

    with db.get_connection() as conn:
        already_applied = get_applied_versions(conn)

    for migration in migrations:
        if migration.version in already_applied:
            logger.debug("Migration %d (%s) already applied.", migration.version, migration.name)
            continue

        logger.info("Applying migration %d: %s", migration.version, migration.name)
        try:
            with db.transaction() as conn:
                conn.executescript(migration.sql)
                conn.execute(
                    "INSERT INTO schema_migrations (version, name) VALUES (?, ?);",
                    (migration.version, migration.name),
                )
            applied_now.append(migration.version)
            logger.info("Successfully applied migration %d.", migration.version)
        except Exception as exc:
            logger.error("Failed to apply migration %d (%s): %s", migration.version, migration.name, exc)
            raise DatabaseMigrationError(
                f"Failed to apply migration {migration.version} ({migration.name}): {exc}"
            ) from exc

    return applied_now
