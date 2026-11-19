"""Unit tests for TracerPyX database repositories."""

from __future__ import annotations

import time
from datetime import datetime
import pytest

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
from tracerpyx.db import (
    AdvisoryRepository,
    CacheRepository,
    DatabaseManager,
    SymbolRepository,
    run_migrations,
)


@pytest.fixture
def test_db() -> DatabaseManager:
    """Provide a migrated in-memory SQLite database instance."""
    db = DatabaseManager(":memory:")
    run_migrations(db)
    yield db
    db.close()


def test_advisory_repository_crud(test_db: DatabaseManager) -> None:
    """Test saving and retrieving an Advisory and its child entities."""
    adv_repo = AdvisoryRepository(test_db)

    ev = SymbolEvidence(
        commit_url="https://github.com/psf/requests/commit/abc1234",
        commit_sha="abc1234",
        file_path="requests/models.py",
        line_start=100,
        line_end=110,
        diff_hunk="@@ -100,10 +100,10 @@",
        rationale="Fixes header parsing flaw",
        extractor=ExtractorType.AST_DIFF,
    )
    sym = VulnerableSymbol(
        symbol_name="requests.models.PreparedRequest.prepare_headers",
        symbol_type="METHOD",
        validation_status=SymbolValidationStatus.CONFIRMED,
        confidence=ConfidenceLevel.HIGH,
        evidence=(ev,),
    )
    pkg = AffectedPackage(
        package_name="requests",
        ecosystem="PyPI",
        version_ranges=(VersionRange(introduced="2.0.0", fixed="2.31.0"),),
        symbols=(sym,),
    )
    ref = AdvisoryReference(
        url="https://github.com/psf/requests/commit/abc1234",
        reference_type=ReferenceType.FIX_COMMIT,
        commit_sha="abc1234",
    )
    adv = Advisory(
        id="GHSA-j8r2-6x86-q33q",
        source="OSV",
        title="Header leak in requests",
        details="Sensitive header leak on cross-domain redirect",
        aliases=("CVE-2023-32681",),
        published_at=datetime(2023, 5, 23, 10, 0, 0),
        modified_at=datetime(2023, 5, 24, 12, 0, 0),
        affected_packages=(pkg,),
        references=(ref,),
        raw_payload='{"id": "GHSA-j8r2-6x86-q33q"}',
    )

    # Save advisory
    adv_repo.save_advisory(adv)
    assert adv_repo.count_advisories() == 1

    # Retrieve by ID
    loaded = adv_repo.get_advisory("GHSA-j8r2-6x86-q33q")
    assert loaded is not None
    assert loaded.id == "GHSA-j8r2-6x86-q33q"
    assert loaded.aliases == ("CVE-2023-32681",)
    assert len(loaded.affected_packages) == 1
    assert loaded.affected_packages[0].package_name == "requests"
    assert len(loaded.affected_packages[0].symbols) == 1

    loaded_sym = loaded.affected_packages[0].symbols[0]
    assert loaded_sym.symbol_name == "requests.models.PreparedRequest.prepare_headers"
    assert loaded_sym.validation_status == SymbolValidationStatus.CONFIRMED
    assert len(loaded_sym.evidence) == 1
    assert loaded_sym.evidence[0].commit_sha == "abc1234"

    # Retrieve by package name (case-insensitive)
    pkg_advisories = adv_repo.get_advisories_for_package("ReQuEsTs")
    assert len(pkg_advisories) == 1
    assert pkg_advisories[0].id == "GHSA-j8r2-6x86-q33q"

    # Non-existent ID returns None
    assert adv_repo.get_advisory("NON-EXISTENT") is None


def test_symbol_repository_queries_and_updates(test_db: DatabaseManager) -> None:
    """Test querying and updating symbols via SymbolRepository."""
    adv_repo = AdvisoryRepository(test_db)
    sym_repo = SymbolRepository(test_db)

    # Prepare and save minimal advisory with 1 package
    pkg = AffectedPackage(package_name="flask", symbols=())
    adv = Advisory(id="GHSA-flask-1", source="OSV", affected_packages=(pkg,))
    adv_repo.save_advisory(adv)

    # Retrieve the affected_package ID
    with test_db.get_connection() as conn:
        pkg_id = conn.execute("SELECT id FROM affected_packages WHERE package_name = 'flask';").fetchone()["id"]

    # Save a candidate symbol
    candidate_sym = VulnerableSymbol(
        symbol_name="flask.app.Flask.add_url_rule",
        symbol_type="METHOD",
        validation_status=SymbolValidationStatus.CANDIDATE,
        confidence=ConfidenceLevel.MEDIUM,
    )
    sym_id = sym_repo.save_symbol(pkg_id, candidate_sym)
    assert sym_id > 0

    # Retrieve symbols
    symbols = sym_repo.get_symbols_for_package_name("flask")
    assert len(symbols) == 1
    assert symbols[0].symbol_name == "flask.app.Flask.add_url_rule"
    assert symbols[0].validation_status == SymbolValidationStatus.CANDIDATE

    # Update status to CONFIRMED
    sym_repo.update_symbol_status(sym_id, SymbolValidationStatus.CONFIRMED, ConfidenceLevel.HIGH)
    updated_symbols = sym_repo.get_symbols_for_package_name("flask")
    assert updated_symbols[0].validation_status == SymbolValidationStatus.CONFIRMED
    assert updated_symbols[0].confidence == ConfidenceLevel.HIGH

    # Update status to REJECTED - with only_usable=True should return 0
    sym_repo.update_symbol_status(sym_id, SymbolValidationStatus.REJECTED)
    assert len(sym_repo.get_symbols_for_package_name("flask", only_usable=True)) == 0
    assert len(sym_repo.get_symbols_for_package_name("flask", only_usable=False)) == 1


def test_cache_repository_set_get_ttl(test_db: DatabaseManager) -> None:
    """Test CacheRepository set, get, TTL expiration, and clear."""
    cache = CacheRepository(test_db)

    # Basic set and get
    cache.set("key1", "RAW_DIFF", "diff --git a/foo b/foo")
    assert cache.get("key1") == "diff --git a/foo b/foo"
    assert cache.count() == 1
    assert cache.count("RAW_DIFF") == 1
    assert cache.count("OTHER") == 0

    # Test TTL expiration (1 second)
    cache.set("short_lived", "TEST", "temporary_val", ttl_seconds=1)
    assert cache.get("short_lived") == "temporary_val"
    time.sleep(1.1)
    # Expired, should return None and be removed
    assert cache.get("short_lived") is None

    # Clear specific type
    cache.set("k2", "TYPE_A", "valA")
    cache.set("k3", "TYPE_B", "valB")
    cleared = cache.clear("TYPE_A")
    assert cleared == 1
    assert cache.get("k2") is None
    assert cache.get("k3") == "valB"

    # Clear all
    cache.clear()
    assert cache.count() == 0
