"""Retrieves, validates, and caches unified diffs and patch files for security fixes."""

from __future__ import annotations

import hashlib
from typing import Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from tracerpyx.core.exceptions import AdvisoryCollectionError
from tracerpyx.core.logging import get_logger
from tracerpyx.core.models import Advisory
from tracerpyx.db.connection import DatabaseManager
from tracerpyx.db.repositories.cache_repo import CacheRepository
from tracerpyx.intelligence.reference_classifier import (
    ClassifiedReference,
    classify_reference,
    find_fix_references,
)

logger = get_logger("intelligence.patch_retriever")

_DEFAULT_MAX_PATCH_SIZE = 5 * 1024 * 1024  # 5 Megabytes


class PatchRetriever:
    """Downloads raw unified diffs and patches with SQLite caching."""

    def __init__(
        self,
        cache_repo: Optional[CacheRepository] = None,
        session: Optional[requests.Session] = None,
        timeout: float = 20.0,
        max_patch_size: int = _DEFAULT_MAX_PATCH_SIZE,
    ) -> None:
        self.cache_repo = cache_repo
        self.timeout = timeout
        self.max_patch_size = max_patch_size

        if session is not None:
            self.session = session
        else:
            self.session = requests.Session()
            retries = Retry(
                total=3,
                backoff_factor=0.5,
                status_forcelist=[429, 500, 502, 503, 504],
                raise_on_status=False,
            )
            adapter = HTTPAdapter(max_retries=retries)
            self.session.mount("https://", adapter)
            self.session.mount("http://", adapter)

    def get_patch_for_reference(
        self,
        reference: ClassifiedReference,
        use_cache: bool = True,
    ) -> Optional[str]:
        """Fetch patch content for a classified reference.

        Args:
            reference: ClassifiedReference instance.
            use_cache: Whether to check and populate CacheRepository.

        Returns:
            Unified diff text, or None if URL is invalid / 404.
        """
        target_url = reference.patch_url or reference.original_url
        if not target_url:
            return None

        # Determine cache key: prefer repo coordinates + SHA, else hash of URL
        if reference.platform and reference.repo_owner and reference.repo_name and reference.commit_sha:
            cache_key = f"patch:{reference.platform}:{reference.repo_owner}:{reference.repo_name}:{reference.commit_sha}"
        else:
            url_hash = hashlib.sha256(target_url.encode("utf-8")).hexdigest()[:16]
            cache_key = f"patch:url:{url_hash}"

        return self.get_patch_from_url(target_url, cache_key=cache_key, use_cache=use_cache)

    def get_patch_from_url(
        self,
        url: str,
        cache_key: Optional[str] = None,
        use_cache: bool = True,
    ) -> Optional[str]:
        """Download raw diff text from a direct URL with caching."""
        if not cache_key:
            url_hash = hashlib.sha256(url.encode("utf-8")).hexdigest()[:16]
            cache_key = f"patch:url:{url_hash}"

        if use_cache and self.cache_repo:
            cached_diff = self.cache_repo.get(cache_key, "RAW_DIFF")
            if cached_diff:
                logger.debug("Cache hit for patch: %s", cache_key)
                return cached_diff

        logger.info("Downloading patch from: %s", url)
        try:
            resp = self.session.get(url, timeout=self.timeout, stream=True)
            if resp.status_code == 404:
                logger.warning("Patch not found (404) at %s", url)
                return None
            resp.raise_for_status()

            # Guard against anomalous massive files
            content_length = resp.headers.get("Content-Length")
            if content_length and int(content_length) > self.max_patch_size:
                logger.warning(
                    "Patch size (%s bytes) exceeds maximum limit (%d bytes): %s",
                    content_length,
                    self.max_patch_size,
                    url,
                )
                return None

            raw_bytes = resp.content
            if len(raw_bytes) > self.max_patch_size:
                logger.warning("Patch content exceeds maximum allowed size: %s", url)
                return None

            diff_text = raw_bytes.decode("utf-8", errors="replace")
        except requests.RequestException as exc:
            logger.error("Failed to download patch from %s: %s", url, exc)
            raise AdvisoryCollectionError(f"Failed to download patch from {url}: {exc}") from exc

        # Cache valid patch
        if use_cache and self.cache_repo and diff_text.strip():
            self.cache_repo.set(cache_key, "RAW_DIFF", diff_text)

        return diff_text


def fetch_and_cache_advisory_patches(
    advisory: Advisory,
    db: DatabaseManager,
    retriever: Optional[PatchRetriever] = None,
    use_cache: bool = True,
) -> dict[str, str]:
    """Discover all fix references for an advisory and cache their patches.

    Args:
        advisory: Advisory domain model.
        db: DatabaseManager instance.
        retriever: Optional configured PatchRetriever.
        use_cache: Whether to use cache.

    Returns:
        Mapping of reference original URL -> unified diff text.
    """
    cache_repo = CacheRepository(db)
    active_retriever = retriever or PatchRetriever(cache_repo=cache_repo)
    fix_refs = find_fix_references(advisory)

    results: dict[str, str] = {}
    for ref in fix_refs:
        diff_text = active_retriever.get_patch_for_reference(ref, use_cache=use_cache)
        if diff_text:
            results[ref.original_url] = diff_text
            logger.debug("Successfully cached patch for %s (%d chars)", ref.original_url, len(diff_text))

    return results
