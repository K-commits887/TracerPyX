"""SQLite database connection and session management for TracerPyX."""

from __future__ import annotations

import sqlite3
from contextlib import contextmanager
from pathlib import Path
from typing import Generator, Optional

from tracerpyx.core.exceptions import DatabaseError
from tracerpyx.core.logging import get_logger

logger = get_logger("db.connection")


class DatabaseManager:
    """Manages SQLite connections with WAL mode and foreign key enforcement."""

    def __init__(self, db_path: str | Path = ":memory:") -> None:
        """Initialize the DatabaseManager.

        Args:
            db_path: Path to the SQLite database file, or ':memory:' for an in-memory DB.
        """
        if db_path != ":memory:":
            self.db_path = str(Path(db_path).expanduser().resolve())
            try:
                Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
            except OSError:
                pass
        else:
            self.db_path = ":memory:"

        # For in-memory DBs, we hold a single persistent connection to preserve state across calls
        self._shared_memory_conn: Optional[sqlite3.Connection] = None
        if self.db_path == ":memory:":
            self._shared_memory_conn = self._create_connection()

    def _create_connection(self) -> sqlite3.Connection:
        """Create and configure a fresh SQLite connection."""
        try:
            if self.db_path != ":memory:":
                try:
                    Path(self.db_path).parent.mkdir(parents=True, exist_ok=True)
                except OSError:
                    pass

            conn = sqlite3.connect(
                self.db_path,
                timeout=30.0,
            )
            conn.row_factory = sqlite3.Row
            # Enable foreign keys
            conn.execute("PRAGMA foreign_keys = ON;")
            # Enable WAL mode for disk files (in-memory ignores WAL)
            if self.db_path != ":memory:":
                conn.execute("PRAGMA journal_mode = WAL;")
            return conn
        except (sqlite3.Error, OSError) as exc:
            raise DatabaseError(f"Failed to connect to database at {self.db_path}: {exc}") from exc

    @contextmanager
    def get_connection(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide a connection context without auto-committing transactions."""
        if self._shared_memory_conn is not None:
            yield self._shared_memory_conn
        else:
            conn = self._create_connection()
            try:
                yield conn
            finally:
                conn.close()

    @contextmanager
    def transaction(self) -> Generator[sqlite3.Connection, None, None]:
        """Provide an atomic transaction context (commits on success, rolls back on error)."""
        if self._shared_memory_conn is not None:
            try:
                yield self._shared_memory_conn
                self._shared_memory_conn.commit()
            except Exception as exc:
                self._shared_memory_conn.rollback()
                logger.error("Transaction rolled back due to error: %s", exc)
                raise DatabaseError(f"Transaction failed: {exc}") from exc
        else:
            conn = self._create_connection()
            try:
                yield conn
                conn.commit()
            except Exception as exc:
                conn.rollback()
                logger.error("Transaction rolled back due to error: %s", exc)
                raise DatabaseError(f"Transaction failed: {exc}") from exc
            finally:
                conn.close()

    def close(self) -> None:
        """Close shared resources (if in-memory)."""
        if self._shared_memory_conn is not None:
            self._shared_memory_conn.close()
            self._shared_memory_conn = None
