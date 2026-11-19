"""Repository layer for querying and updating VulnerableSymbol entities."""

from __future__ import annotations

import sqlite3
from typing import Optional

from tracerpyx.core.enums import (
    ConfidenceLevel,
    ExtractorType,
    SymbolValidationStatus,
)
from tracerpyx.core.models import SymbolEvidence, VulnerableSymbol
from tracerpyx.db.connection import DatabaseManager


class SymbolRepository:
    """Handles persistence and retrieval of VulnerableSymbols and associated patch evidence."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save_symbol(self, affected_package_id: int, symbol: VulnerableSymbol) -> int:
        """Insert or update a vulnerable symbol record and its evidence."""
        with self.db.transaction() as conn:
            cursor = conn.execute(
                """
                INSERT INTO vulnerable_symbols (affected_package_id, symbol_name, symbol_type, validation_status, confidence)
                VALUES (?, ?, ?, ?, ?);
                """,
                (
                    affected_package_id,
                    symbol.symbol_name,
                    symbol.symbol_type,
                    symbol.validation_status.value,
                    symbol.confidence.value,
                ),
            )
            symbol_id = cursor.lastrowid

            for ev in symbol.evidence:
                conn.execute(
                    """
                    INSERT INTO symbol_evidence (symbol_id, commit_url, commit_sha, file_path, line_start, line_end, diff_hunk, rationale, extractor)
                    VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                    """,
                    (
                        symbol_id,
                        ev.commit_url,
                        ev.commit_sha,
                        ev.file_path,
                        ev.line_start,
                        ev.line_end,
                        ev.diff_hunk,
                        ev.rationale,
                        ev.extractor.value,
                    ),
                )
            return int(symbol_id)

    def update_symbol_status(
        self,
        symbol_id: int,
        status: SymbolValidationStatus,
        confidence: Optional[ConfidenceLevel] = None,
    ) -> None:
        """Update the validation status and optionally confidence of a symbol."""
        with self.db.transaction() as conn:
            if confidence:
                conn.execute(
                    "UPDATE vulnerable_symbols SET validation_status = ?, confidence = ? WHERE id = ?;",
                    (status.value, confidence.value, symbol_id),
                )
            else:
                conn.execute(
                    "UPDATE vulnerable_symbols SET validation_status = ? WHERE id = ?;",
                    (status.value, symbol_id),
                )

    def get_symbols_for_package_id(self, affected_package_id: int) -> list[VulnerableSymbol]:
        """Fetch all symbols attached to an affected_package row."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                "SELECT * FROM vulnerable_symbols WHERE affected_package_id = ? ORDER BY id ASC;",
                (affected_package_id,),
            ).fetchall()
            return [self._build_symbol(conn, r) for r in rows]

    def get_symbols_for_package_name(
        self,
        package_name: str,
        only_usable: bool = True,
    ) -> list[VulnerableSymbol]:
        """Fetch all vulnerable symbols for a package across all advisories."""
        with self.db.get_connection() as conn:
            query = """
                SELECT s.* FROM vulnerable_symbols s
                JOIN affected_packages ap ON s.affected_package_id = ap.id
                WHERE ap.package_name = ? COLLATE NOCASE
            """
            if only_usable:
                query += " AND s.validation_status IN ('CONFIRMED', 'CANDIDATE')"
            query += " ORDER BY s.id ASC;"

            rows = conn.execute(query, (package_name,)).fetchall()
            return [self._build_symbol(conn, r) for r in rows]

    def _build_symbol(self, conn: sqlite3.Connection, row: sqlite3.Row) -> VulnerableSymbol:
        sym_id = row["id"]
        ev_rows = conn.execute(
            "SELECT * FROM symbol_evidence WHERE symbol_id = ? ORDER BY id ASC;",
            (sym_id,),
        ).fetchall()
        evidence = tuple(
            SymbolEvidence(
                commit_url=ev["commit_url"],
                commit_sha=ev["commit_sha"],
                file_path=ev["file_path"],
                line_start=ev["line_start"],
                line_end=ev["line_end"],
                diff_hunk=ev["diff_hunk"],
                rationale=ev["rationale"],
                extractor=ExtractorType(ev["extractor"]),
            )
            for ev in ev_rows
        )
        return VulnerableSymbol(
            symbol_name=row["symbol_name"],
            symbol_type=row["symbol_type"],
            validation_status=SymbolValidationStatus(row["validation_status"]),
            confidence=ConfidenceLevel(row["confidence"]),
            evidence=evidence,
        )
