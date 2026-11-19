"""Repository layer for persisting and retrieving Advisory records."""

from __future__ import annotations

import json
import sqlite3
from datetime import datetime
from typing import Optional

from tracerpyx.core.enums import (
    ConfidenceLevel,
    ExtractorType,
    ReferenceType,
    SymbolValidationStatus,
)
from tracerpyx.core.models import (
    Advisory,
    AdvisoryReference,
    AffectedPackage,
    SymbolEvidence,
    VersionRange,
    VulnerableSymbol,
)
from tracerpyx.db.connection import DatabaseManager


class AdvisoryRepository:
    """Handles SQLite persistence for Advisories and AffectedPackages."""

    def __init__(self, db: DatabaseManager) -> None:
        self.db = db

    def save_advisory(self, advisory: Advisory) -> None:
        """Persist an advisory along with its affected packages, references, and symbols."""
        with self.db.transaction() as conn:
            # Upsert into advisories
            aliases_json = json.dumps(list(advisory.aliases))
            pub_str = advisory.published_at.isoformat() if advisory.published_at else None
            mod_str = advisory.modified_at.isoformat() if advisory.modified_at else None

            conn.execute(
                """
                INSERT INTO advisories (id, source, aliases, title, details, published_at, modified_at, raw_payload)
                VALUES (?, ?, ?, ?, ?, ?, ?, ?)
                ON CONFLICT(id) DO UPDATE SET
                    source=excluded.source,
                    aliases=excluded.aliases,
                    title=excluded.title,
                    details=excluded.details,
                    published_at=excluded.published_at,
                    modified_at=excluded.modified_at,
                    raw_payload=excluded.raw_payload;
                """,
                (
                    advisory.id,
                    advisory.source,
                    aliases_json,
                    advisory.title,
                    advisory.details,
                    pub_str,
                    mod_str,
                    advisory.raw_payload,
                ),
            )

            # Clear existing child records for this advisory to ensure atomic replacement
            conn.execute("DELETE FROM affected_packages WHERE advisory_id = ?;", (advisory.id,))
            conn.execute("DELETE FROM advisory_references WHERE advisory_id = ?;", (advisory.id,))

            # Insert references
            for ref in advisory.references:
                conn.execute(
                    """
                    INSERT INTO advisory_references (advisory_id, url, reference_type, commit_sha)
                    VALUES (?, ?, ?, ?);
                    """,
                    (advisory.id, ref.url, ref.reference_type.value, ref.commit_sha),
                )

            # Insert affected packages and their symbols
            for pkg in advisory.affected_packages:
                vr_list = [
                    {"introduced": vr.introduced, "fixed": vr.fixed, "last_affected": vr.last_affected}
                    for vr in pkg.version_ranges
                ]
                vr_json = json.dumps(vr_list)

                cursor = conn.execute(
                    """
                    INSERT INTO affected_packages (advisory_id, package_name, ecosystem, version_range_raw)
                    VALUES (?, ?, ?, ?);
                    """,
                    (advisory.id, pkg.package_name, pkg.ecosystem, vr_json),
                )
                pkg_id = cursor.lastrowid

                # Insert vulnerable symbols
                for sym in pkg.symbols:
                    sym_cursor = conn.execute(
                        """
                        INSERT INTO vulnerable_symbols (affected_package_id, symbol_name, symbol_type, validation_status, confidence)
                        VALUES (?, ?, ?, ?, ?);
                        """,
                        (pkg_id, sym.symbol_name, sym.symbol_type, sym.validation_status.value, sym.confidence.value),
                    )
                    sym_id = sym_cursor.lastrowid

                    # Insert evidence
                    for ev in sym.evidence:
                        conn.execute(
                            """
                            INSERT INTO symbol_evidence (symbol_id, commit_url, commit_sha, file_path, line_start, line_end, diff_hunk, rationale, extractor)
                            VALUES (?, ?, ?, ?, ?, ?, ?, ?, ?);
                            """,
                            (
                                sym_id,
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

    def get_advisory(self, advisory_id: str) -> Optional[Advisory]:
        """Fetch an advisory by its unique ID (e.g. 'GHSA-xxx' or 'PYSEC-xxx')."""
        with self.db.get_connection() as conn:
            row = conn.execute(
                "SELECT * FROM advisories WHERE id = ?;", (advisory_id,)
            ).fetchone()
            if not row:
                return None

            return self._build_advisory_from_row(conn, row)

    def get_advisories_for_package(self, package_name: str) -> list[Advisory]:
        """Retrieve all advisories affecting a package name (case-insensitive)."""
        with self.db.get_connection() as conn:
            rows = conn.execute(
                """
                SELECT DISTINCT a.* FROM advisories a
                JOIN affected_packages ap ON a.id = ap.advisory_id
                WHERE ap.package_name = ? COLLATE NOCASE
                ORDER BY a.published_at DESC;
                """,
                (package_name,),
            ).fetchall()

            return [self._build_advisory_from_row(conn, row) for row in rows]

    def count_advisories(self) -> int:
        """Return total number of stored advisories."""
        with self.db.get_connection() as conn:
            row = conn.execute("SELECT COUNT(*) AS cnt FROM advisories;").fetchone()
            return int(row["cnt"]) if row else 0

    def _build_advisory_from_row(self, conn: sqlite3.Connection, row: sqlite3.Row) -> Advisory:
        """Helper to reconstruct an Advisory domain model from DB rows."""
        advisory_id = row["id"]

        # Parse aliases
        aliases = tuple(json.loads(row["aliases"])) if row["aliases"] else ()

        # Parse dates
        pub = datetime.fromisoformat(row["published_at"]) if row["published_at"] else None
        mod = datetime.fromisoformat(row["modified_at"]) if row["modified_at"] else None

        # Fetch references
        ref_rows = conn.execute(
            "SELECT * FROM advisory_references WHERE advisory_id = ? ORDER BY id ASC;",
            (advisory_id,),
        ).fetchall()
        references = tuple(
            AdvisoryReference(
                url=r["url"],
                reference_type=ReferenceType(r["reference_type"]),
                commit_sha=r["commit_sha"],
            )
            for r in ref_rows
        )

        # Fetch affected packages
        pkg_rows = conn.execute(
            "SELECT * FROM affected_packages WHERE advisory_id = ? ORDER BY id ASC;",
            (advisory_id,),
        ).fetchall()

        affected_packages = []
        for pkg_row in pkg_rows:
            pkg_id = pkg_row["id"]
            vr_raw = json.loads(pkg_row["version_range_raw"]) if pkg_row["version_range_raw"] else []
            version_ranges = tuple(
                VersionRange(
                    introduced=item.get("introduced", "0"),
                    fixed=item.get("fixed"),
                    last_affected=item.get("last_affected"),
                )
                for item in vr_raw
            )

            # Fetch symbols for this package
            sym_rows = conn.execute(
                "SELECT * FROM vulnerable_symbols WHERE affected_package_id = ? ORDER BY id ASC;",
                (pkg_id,),
            ).fetchall()

            symbols = []
            for sym_row in sym_rows:
                sym_id = sym_row["id"]
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
                symbols.append(
                    VulnerableSymbol(
                        symbol_name=sym_row["symbol_name"],
                        symbol_type=sym_row["symbol_type"],
                        validation_status=SymbolValidationStatus(sym_row["validation_status"]),
                        confidence=ConfidenceLevel(sym_row["confidence"]),
                        evidence=evidence,
                    )
                )

            affected_packages.append(
                AffectedPackage(
                    package_name=pkg_row["package_name"],
                    ecosystem=pkg_row["ecosystem"],
                    version_ranges=version_ranges,
                    symbols=tuple(symbols),
                )
            )

        return Advisory(
            id=advisory_id,
            source=row["source"],
            aliases=aliases,
            title=row["title"] or "",
            details=row["details"] or "",
            published_at=pub,
            modified_at=mod,
            affected_packages=tuple(affected_packages),
            references=references,
            raw_payload=row["raw_payload"],
        )
