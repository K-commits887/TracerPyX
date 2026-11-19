"""Unit tests for OSV advisory client and normalization pipeline."""

from __future__ import annotations

import json
from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

from tracerpyx.core.enums import ReferenceType
from tracerpyx.core.exceptions import AdvisoryCollectionError
from tracerpyx.db import AdvisoryRepository, CacheRepository, DatabaseManager, run_migrations
from tracerpyx.intelligence.osv_collector import OSVClient, sync_package_advisories

_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "advisories"


@pytest.fixture
def test_db() -> DatabaseManager:
    """Provide a migrated in-memory SQLite database."""
    db = DatabaseManager(":memory:")
    run_migrations(db)
    yield db
    db.close()


@pytest.fixture
def mock_session() -> MagicMock:
    """Mock requests.Session avoiding external network calls."""
    session = MagicMock(spec=requests.Session)
    return session


def test_normalize_osv_payload_full() -> None:
    """Ensure raw OSV payload normalizes into canonical Advisory domain models."""
    fixture_path = _FIXTURES_DIR / "requests_ghsa_j8r2.json"
    raw_data = json.loads(fixture_path.read_text(encoding="utf-8"))

    client = OSVClient()
    advisory = client.normalize_osv_payload(raw_data)

    assert advisory.id == "GHSA-j8r2-6x86-q33q"
    assert advisory.source == "GHSA"
    assert advisory.aliases == ("CVE-2023-32681",)
    assert "Proxy-Authorization" in advisory.title
    assert advisory.published_at is not None
    assert advisory.published_at.year == 2023

    # Packages & ranges
    assert len(advisory.affected_packages) == 1
    pkg = advisory.affected_packages[0]
    assert pkg.package_name == "requests"
    assert pkg.ecosystem == "PyPI"
    assert len(pkg.version_ranges) == 1
    vr = pkg.version_ranges[0]
    assert vr.introduced == "2.3.0"
    assert vr.fixed == "2.31.0"

    # References & Commit SHA extraction
    assert len(advisory.references) == 3
    fix_ref = next(r for r in advisory.references if r.reference_type == ReferenceType.FIX_COMMIT)
    assert fix_ref.commit_sha == "7492dc4879e37fc361099b2447990db207567702"


def test_query_package_with_caching(mock_session: MagicMock, test_db: DatabaseManager) -> None:
    """Test package query and verify that subsequent calls resolve from cache without network."""
    fixture_path = _FIXTURES_DIR / "osv_query_requests.json"
    fake_json = json.loads(fixture_path.read_text(encoding="utf-8"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_json
    mock_session.post.return_value = mock_resp

    cache_repo = CacheRepository(test_db)
    client = OSVClient(session=mock_session, cache_repo=cache_repo)

    # First call: hits session.post and writes to cache
    advisories = client.query_package("requests")
    assert len(advisories) == 2
    assert mock_session.post.call_count == 1
    assert cache_repo.count("OSV_QUERY") == 1

    # Second call: hits cache, session.post NOT called again
    advisories_cached = client.query_package("requests")
    assert len(advisories_cached) == 2
    assert mock_session.post.call_count == 1  # Still 1!


def test_get_vuln_by_id_success_and_404(mock_session: MagicMock, test_db: DatabaseManager) -> None:
    """Test get_vuln_by_id handling both 200 OK and 404 Not Found."""
    fixture_path = _FIXTURES_DIR / "requests_ghsa_j8r2.json"
    fake_json = json.loads(fixture_path.read_text(encoding="utf-8"))

    # 200 OK response
    mock_resp_ok = MagicMock()
    mock_resp_ok.status_code = 200
    mock_resp_ok.json.return_value = fake_json

    # 404 response
    mock_resp_404 = MagicMock()
    mock_resp_404.status_code = 404

    def side_effect(url: str, **kwargs: object) -> MagicMock:
        if "GHSA-j8r2-6x86-q33q" in url:
            return mock_resp_ok
        return mock_resp_404

    mock_session.get.side_effect = side_effect

    client = OSVClient(session=mock_session, cache_repo=CacheRepository(test_db))
    adv = client.get_vuln_by_id("GHSA-j8r2-6x86-q33q")
    assert adv is not None
    assert adv.id == "GHSA-j8r2-6x86-q33q"

    # Non-existent ID returns None
    missing = client.get_vuln_by_id("GHSA-does-not-exist")
    assert missing is None


def test_query_package_network_error(mock_session: MagicMock) -> None:
    """Ensure network failure raises AdvisoryCollectionError."""
    mock_session.post.side_effect = requests.ConnectionError("Connection refused")
    client = OSVClient(session=mock_session)

    with pytest.raises(AdvisoryCollectionError) as exc_info:
        client.query_package("requests")
    assert "Failed to query OSV for package 'requests'" in str(exc_info.value)


def test_sync_package_advisories_end_to_end(mock_session: MagicMock, test_db: DatabaseManager) -> None:
    """Test sync_package_advisories orchestrating API fetch and DB persistence."""
    fixture_path = _FIXTURES_DIR / "osv_query_requests.json"
    fake_json = json.loads(fixture_path.read_text(encoding="utf-8"))

    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.json.return_value = fake_json
    mock_session.post.return_value = mock_resp

    client = OSVClient(session=mock_session, cache_repo=CacheRepository(test_db))
    synced = sync_package_advisories("requests", test_db, client=client)

    assert len(synced) == 2

    # Verify directly in database
    adv_repo = AdvisoryRepository(test_db)
    assert adv_repo.count_advisories() == 2
    loaded = adv_repo.get_advisories_for_package("requests")
    assert len(loaded) == 2
    loaded_ids = {a.id for a in loaded}
    assert "GHSA-j8r2-6x86-q33q" in loaded_ids
    assert "PYSEC-2018-28" in loaded_ids
