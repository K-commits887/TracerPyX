"""Repository for general-purpose persistent caching in SQLite."""

from __future__ import annotations

from datetime import datetime, timedelta
from typing import Optional

from tracerpyx.db.connection import DatabaseManager


class CacheRepository:
    """Provides key-value caching with optional TTL in SQLite."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def get(self, cache_key: str, cache_type: Optional[str] = None) -> Optional[str]:
        """Retrieve cached payload if it exists and has not expired."""
        with self.db.get_connection() as conn:
            query = "SELECT payload, expires_at FROM analysis_cache WHERE cache_key = ?"
            params: list[str] = [cache_key]
            if cache_type:
                query += " AND cache_type = ?"
                params.append(cache_type)

            row = conn.execute(query, params).fetchone()
            if not row:
                return None

            expires_at = row["expires_at"]
            if expires_at:
                exp_dt = datetime.fromisoformat(expires_at)
                if datetime.now() > exp_dt:
                    # Expired, clean up and return None
                    self.delete(cache_key)
                    return None

            return str(row["payload"])

    def set(
        self,
        cache_key: str,
        cache_type: str,
        payload: str,
        ttl_seconds: Optional[int] = None,
    ) -> None:
        """Store or update a payload in the cache."""
        exp_str = None
        if ttl_seconds is not None:
            exp_dt = datetime.now() + timedelta(seconds=ttl_seconds)
            exp_str = exp_dt.isoformat()

        with self.db.transaction() as conn:
            conn.execute(
                """
                INSERT INTO analysis_cache (cache_key, cache_type, payload, expires_at)
                VALUES (?, ?, ?, ?)
                ON CONFLICT(cache_key) DO UPDATE SET
                    cache_type=excluded.cache_type,
                    payload=excluded.payload,
                    expires_at=excluded.expires_at,
                    created_at=CURRENT_TIMESTAMP;
                """,
                (cache_key, cache_type, payload, exp_str),
            )

    def delete(self, cache_key: str) -> None:
        """Delete an entry from the cache."""
        with self.db.transaction() as conn:
            conn.execute("DELETE FROM analysis_cache WHERE cache_key = ?;", (cache_key,))

    def clear(self, cache_type: Optional[str] = None) -> int:
        """Purge all entries or entries of a specific cache_type."""
        with self.db.transaction() as conn:
            if cache_type:
                cursor = conn.execute(
                    "DELETE FROM analysis_cache WHERE cache_type = ?;", (cache_type,)
                )
            else:
                cursor = conn.execute("DELETE FROM analysis_cache;")
            return cursor.rowcount

    def count(self, cache_type: Optional[str] = None) -> int:
        """Count active entries in cache."""
        with self.db.get_connection() as conn:
            if cache_type:
                row = conn.execute(
                    "SELECT COUNT(*) AS cnt FROM analysis_cache WHERE cache_type = ?;",
                    (cache_type,),
                ).fetchone()
            else:
                row = conn.execute("SELECT COUNT(*) AS cnt FROM analysis_cache;").fetchone()
            return int(row["cnt"]) if row else 0
