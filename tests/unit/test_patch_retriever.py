"""Unit tests for patch retrieval and SQLite caching."""

from __future__ import annotations

from pathlib import Path
from unittest.mock import MagicMock

import pytest
import requests

from tracerpyx.core.enums import ReferenceType
from tracerpyx.core.exceptions import AdvisoryCollectionError
from tracerpyx.core.models import Advisory, AdvisoryReference
from tracerpyx.db import CacheRepository, DatabaseManager, run_migrations
from tracerpyx.intelligence.patch_retriever import (
    PatchRetriever,
    fetch_and_cache_advisory_patches,
)
from tracerpyx.intelligence.reference_classifier import ClassifiedReference

_FIXTURES_DIR = Path(__file__).parent.parent / "fixtures" / "diffs"


@pytest.fixture
def test_db() -> DatabaseManager:
    """Provide a migrated in-memory SQLite database."""
    db = DatabaseManager(":memory:")
    run_migrations(db)
    yield db
    db.close()


@pytest.fixture
def sample_diff() -> str:
    """Load real sample diff fixture."""
    diff_file = _FIXTURES_DIR / "requests_cve_2023_32681.diff"
    return diff_file.read_text(encoding="utf-8")


def test_get_patch_for_reference_caching(sample_diff: str, test_db: DatabaseManager) -> None:
    """Ensure patch is retrieved from URL and subsequent requests hit the SQLite cache."""
    mock_session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = sample_diff.encode("utf-8")
    mock_resp.headers = {"Content-Length": str(len(mock_resp.content))}
    mock_session.get.return_value = mock_resp

    cache_repo = CacheRepository(test_db)
    retriever = PatchRetriever(cache_repo=cache_repo, session=mock_session)

    ref = ClassifiedReference(
        original_url="https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702",
        reference_type=ReferenceType.FIX_COMMIT,
        platform="github",
        repo_owner="psf",
        repo_name="requests",
        commit_sha="7492dc4879e37fc361099b2447990db207567702",
        patch_url="https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702.patch",
    )

    # First fetch: downloads and populates cache
    patch_text = retriever.get_patch_for_reference(ref)
    assert patch_text is not None
    assert "rebuild_proxies" in patch_text
    assert mock_session.get.call_count == 1
    assert cache_repo.count("RAW_DIFF") == 1

    # Second fetch: served from SQLite cache
    cached_text = retriever.get_patch_for_reference(ref)
    assert cached_text == patch_text
    assert mock_session.get.call_count == 1  # No additional network hit!


def test_get_patch_404_handling(test_db: DatabaseManager) -> None:
    """Ensure 404 responses return None cleanly without exceptions."""
    mock_session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 404
    mock_session.get.return_value = mock_resp

    retriever = PatchRetriever(cache_repo=CacheRepository(test_db), session=mock_session)
    res = retriever.get_patch_from_url("https://github.com/org/repo/commit/invalid.patch")
    assert res is None


def test_get_patch_size_limit_rejection(test_db: DatabaseManager) -> None:
    """Ensure patches exceeding max_patch_size are safely rejected."""
    mock_session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.headers = {"Content-Length": "10485760"}  # 10MB
    mock_resp.content = b"x" * 10485760
    mock_session.get.return_value = mock_resp

    retriever = PatchRetriever(
        cache_repo=CacheRepository(test_db),
        session=mock_session,
        max_patch_size=1024 * 1024,  # 1MB limit
    )

    result = retriever.get_patch_from_url("https://github.com/org/repo/commit/huge.patch")
    assert result is None


def test_get_patch_network_failure(test_db: DatabaseManager) -> None:
    """Ensure network failure raises AdvisoryCollectionError."""
    mock_session = MagicMock(spec=requests.Session)
    mock_session.get.side_effect = requests.Timeout("Connection timed out")

    retriever = PatchRetriever(cache_repo=CacheRepository(test_db), session=mock_session)
    with pytest.raises(AdvisoryCollectionError) as exc_info:
        retriever.get_patch_from_url("https://github.com/org/repo/commit/timeout.patch")
    assert "Failed to download patch" in str(exc_info.value)


def test_fetch_and_cache_advisory_patches_end_to_end(sample_diff: str, test_db: DatabaseManager) -> None:
    """Ensure fetch_and_cache_advisory_patches resolves fix references and stores diffs."""
    mock_session = MagicMock(spec=requests.Session)
    mock_resp = MagicMock()
    mock_resp.status_code = 200
    mock_resp.content = sample_diff.encode("utf-8")
    mock_resp.headers = {"Content-Length": str(len(mock_resp.content))}
    mock_session.get.return_value = mock_resp

    advisory = Advisory(
        id="GHSA-j8r2-6x86-q33q",
        source="GHSA",
        references=(
            AdvisoryReference(
                url="https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702",
                reference_type=ReferenceType.FIX_COMMIT,
                commit_sha="7492dc4879e37fc361099b2447990db207567702",
            ),
        ),
    )

    cache_repo = CacheRepository(test_db)
    retriever = PatchRetriever(cache_repo=cache_repo, session=mock_session)
    patches = fetch_and_cache_advisory_patches(advisory, test_db, retriever=retriever)

    assert len(patches) == 1
    assert "https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702" in patches
    assert "rebuild_proxies" in patches["https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702"]

    # Verify cache row
    assert cache_repo.count("RAW_DIFF") == 1
