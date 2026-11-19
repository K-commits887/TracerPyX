"""Unit tests for SQLite database connection, transactions, and migrations."""

from __future__ import annotations

from pathlib import Path
import sqlite3
import pytest

from tracerpyx.core.exceptions import DatabaseError
from tracerpyx.db import (
    DatabaseManager,
    get_applied_versions,
    run_migrations,
)


def test_database_manager_in_memory() -> None:
    """Ensure in-memory DatabaseManager preserves tables across connection calls."""
    db = DatabaseManager(":memory:")
    with db.transaction() as conn:
        conn.execute("CREATE TABLE test_tab (id INTEGER PRIMARY KEY, val TEXT);")
        conn.execute("INSERT INTO test_tab (val) VALUES ('abc');")

    with db.get_connection() as conn:
        row = conn.execute("SELECT val FROM test_tab;").fetchone()
        assert row["val"] == "abc"
    db.close()


def test_database_manager_transaction_rollback() -> None:
    """Ensure DatabaseManager transaction rolls back changes when an error is raised."""
    db = DatabaseManager(":memory:")
    with db.transaction() as conn:
        conn.execute("CREATE TABLE accounts (id INTEGER PRIMARY KEY, balance INT);")
        conn.execute("INSERT INTO accounts VALUES (1, 100);")

    with pytest.raises(DatabaseError):
        with db.transaction() as conn:
            conn.execute("UPDATE accounts SET balance = 50 WHERE id = 1;")
            raise RuntimeError("Deliberate failure to test rollback")

    with db.get_connection() as conn:
        row = conn.execute("SELECT balance FROM accounts WHERE id = 1;").fetchone()
        assert row["balance"] == 100  # Preserved original balance
    db.close()


def test_migrations_application_and_idempotence() -> None:
    """Ensure run_migrations applies schema version 1 and subsequent runs do nothing."""
    db = DatabaseManager(":memory:")
    with db.get_connection() as conn:
        assert len(get_applied_versions(conn)) == 0

    applied_first = run_migrations(db)
    assert 1 in applied_first

    with db.get_connection() as conn:
        applied_versions = get_applied_versions(conn)
        assert 1 in applied_versions

    # Second run should apply nothing
    applied_second = run_migrations(db)
    assert applied_second == []
    db.close()


def test_foreign_key_enforcement() -> None:
    """Ensure PRAGMA foreign_keys is strictly enforced."""
    db = DatabaseManager(":memory:")
    run_migrations(db)

    # Attempt to insert an affected_package pointing to a nonexistent advisory
    with pytest.raises(DatabaseError) as exc_info:
        with db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO affected_packages (advisory_id, package_name, ecosystem, version_range_raw)
                VALUES ('NONEXISTENT-ID', 'requests', 'PyPI', '[]');
                """
            )
    assert "FOREIGN KEY constraint failed" in str(exc_info.value)
    db.close()


def test_file_based_database(tmp_path: Path) -> None:
    """Ensure file-based database initializes, applies migrations, and closes cleanly."""
    db_file = tmp_path / "subdir" / "test.db"
    db = DatabaseManager(db_file)
    applied = run_migrations(db)
    assert 1 in applied

    assert db_file.exists()
    with db.get_connection() as conn:
        journal_mode = conn.execute("PRAGMA journal_mode;").fetchone()[0]
        # WAL mode is active for file DBs
        assert journal_mode.lower() == "wal"
    db.close()
