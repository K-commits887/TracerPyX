"""OSV (Open Source Vulnerabilities) API client and advisory normalizer."""

from __future__ import annotations

import json
import re
from datetime import datetime
from typing import Any, Optional

import requests
from requests.adapters import HTTPAdapter
from urllib3.util.retry import Retry

from tracerpyx.core.enums import ReferenceType
from tracerpyx.core.exceptions import AdvisoryCollectionError
from tracerpyx.core.logging import get_logger
from tracerpyx.core.models import (
    Advisory,
    AdvisoryReference,
    AffectedPackage,
    VersionRange,
)
from tracerpyx.db.connection import DatabaseManager
from tracerpyx.db.repositories.advisory_repo import AdvisoryRepository
from tracerpyx.db.repositories.cache_repo import CacheRepository

logger = get_logger("intelligence.osv")

_COMMIT_URL_REGEX = re.compile(
    r"https?://(?:www\.)?github\.com/[^/]+/[^/]+/commit/([0-9a-fA-F]{7,40})"
)


class OSVClient:
    """HTTP client for querying the OSV vulnerability database."""

    def __init__(
        self,
        base_url: str = "https://api.osv.dev/v1",
        timeout: float = 15.0,
        cache_repo: Optional[CacheRepository] = None,
        session: Optional[requests.Session] = None,
    ) -> None:
        self.base_url = base_url.rstrip("/")
        self.timeout = timeout
        self.cache_repo = cache_repo

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

    def query_package(
        self,
        package_name: str,
        ecosystem: str = "PyPI",
        use_cache: bool = True,
    ) -> list[Advisory]:
        """Query all advisories affecting a package name in an ecosystem.

        Args:
            package_name: Name of package (e.g. 'requests', 'flask').
            ecosystem: Target ecosystem (defaults to 'PyPI').
            use_cache: Whether to inspect and write to CacheRepository.

        Returns:
            List of normalized Advisory domain models.
        """
        cache_key = f"osv:pkg:{ecosystem.lower()}:{package_name.lower()}"
        if use_cache and self.cache_repo:
            cached_json = self.cache_repo.get(cache_key, "OSV_QUERY")
            if cached_json:
                logger.debug("Cache hit for OSV query: %s", cache_key)
                data = json.loads(cached_json)
                return [self.normalize_osv_payload(v) for v in data.get("vulns", [])]

        url = f"{self.base_url}/query"
        payload = {"package": {"name": package_name, "ecosystem": ecosystem}}

        logger.info("Querying OSV for package '%s' (%s)", package_name, ecosystem)
        try:
            resp = self.session.post(url, json=payload, timeout=self.timeout)
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("OSV API query failed for package '%s': %s", package_name, exc)
            raise AdvisoryCollectionError(
                f"Failed to query OSV for package '{package_name}': {exc}"
            ) from exc

        # Cache raw response (24 hour TTL by default)
        if use_cache and self.cache_repo:
            self.cache_repo.set(cache_key, "OSV_QUERY", json.dumps(data), ttl_seconds=86400)

        vulns = data.get("vulns", [])
        return [self.normalize_osv_payload(v) for v in vulns]

    def get_vuln_by_id(
        self,
        advisory_id: str,
        use_cache: bool = True,
    ) -> Optional[Advisory]:
        """Fetch an individual advisory by ID (e.g. 'GHSA-xxx' or 'PYSEC-xxx')."""
        cache_key = f"osv:vuln:{advisory_id}"
        if use_cache and self.cache_repo:
            cached_json = self.cache_repo.get(cache_key, "OSV_VULN")
            if cached_json:
                logger.debug("Cache hit for advisory %s", advisory_id)
                return self.normalize_osv_payload(json.loads(cached_json))

        url = f"{self.base_url}/vulns/{advisory_id}"
        logger.info("Fetching OSV advisory: %s", advisory_id)
        try:
            resp = self.session.get(url, timeout=self.timeout)
            if resp.status_code == 404:
                return None
            resp.raise_for_status()
            data = resp.json()
        except requests.RequestException as exc:
            logger.error("Failed to fetch OSV advisory %s: %s", advisory_id, exc)
            raise AdvisoryCollectionError(
                f"Failed to fetch OSV advisory '{advisory_id}': {exc}"
            ) from exc

        if use_cache and self.cache_repo:
            self.cache_repo.set(cache_key, "OSV_VULN", json.dumps(data), ttl_seconds=86400)

        return self.normalize_osv_payload(data)

    def normalize_osv_payload(self, raw: dict[str, Any]) -> Advisory:
        """Convert a raw OSV JSON vulnerability schema into an Advisory domain model."""
        adv_id = raw.get("id", "UNKNOWN")
        source = "OSV"
        if adv_id.startswith("GHSA"):
            source = "GHSA"
        elif adv_id.startswith("PYSEC"):
            source = "PYPA"

        title = raw.get("summary", "") or ""
        details = raw.get("details", "") or ""
        aliases = tuple(raw.get("aliases", []))

        # Parse dates
        pub_dt = self._parse_iso_date(raw.get("published"))
        mod_dt = self._parse_iso_date(raw.get("modified"))

        # References
        references: list[AdvisoryReference] = []
        for ref in raw.get("references", []):
            url = ref.get("url", "").strip()
            if not url:
                continue
            ref_type_raw = str(ref.get("type", "UNKNOWN")).upper()
            ref_type = self._map_reference_type(ref_type_raw, url)

            # Extract commit SHA if applicable
            commit_sha = None
            match = _COMMIT_URL_REGEX.search(url)
            if match:
                commit_sha = match.group(1)
                ref_type = ReferenceType.FIX_COMMIT

            references.append(
                AdvisoryReference(
                    url=url,
                    reference_type=ref_type,
                    commit_sha=commit_sha,
                )
            )

        # Affected Packages
        affected_packages: list[AffectedPackage] = []
        for aff in raw.get("affected", []):
            pkg_info = aff.get("package", {})
            pkg_name = pkg_info.get("name", "")
            ecosystem = pkg_info.get("ecosystem", "PyPI")

            version_ranges: list[VersionRange] = []
            for rng in aff.get("ranges", []):
                events = rng.get("events", [])
                intro_val = "0"
                fixed_val = None
                last_affected_val = None

                for evt in events:
                    if "introduced" in evt:
                        intro_val = str(evt["introduced"])
                    elif "fixed" in evt:
                        fixed_val = str(evt["fixed"])
                    elif "last_affected" in evt:
                        last_affected_val = str(evt["last_affected"])

                version_ranges.append(
                    VersionRange(
                        introduced=intro_val,
                        fixed=fixed_val,
                        last_affected=last_affected_val,
                    )
                )

            # If no ranges but explicit versions list provided
            if not version_ranges and "versions" in aff:
                for v in aff["versions"]:
                    version_ranges.append(VersionRange(introduced=v, last_affected=v))

            affected_packages.append(
                AffectedPackage(
                    package_name=pkg_name,
                    ecosystem=ecosystem,
                    version_ranges=tuple(version_ranges),
                    symbols=(),
                )
            )

        return Advisory(
            id=adv_id,
            source=source,
            title=title,
            details=details,
            aliases=aliases,
            published_at=pub_dt,
            modified_at=mod_dt,
            affected_packages=tuple(affected_packages),
            references=tuple(references),
            raw_payload=json.dumps(raw),
        )

    @staticmethod
    def _parse_iso_date(date_str: Optional[str]) -> Optional[datetime]:
        if not date_str:
            return None
        try:
            # Handle standard 'Z' suffix
            clean_str = date_str.replace("Z", "+00:00")
            return datetime.fromisoformat(clean_str)
        except (ValueError, TypeError):
            return None

    @staticmethod
    def _map_reference_type(ref_type_str: str, url: str) -> ReferenceType:
        if ref_type_str == "FIX" or "/commit/" in url:
            return ReferenceType.FIX_COMMIT
        elif ref_type_str in ("ADVISORY", "REPORT"):
            return ReferenceType.ADVISORY
        elif "/pull/" in url:
            return ReferenceType.PULL_REQUEST
        elif "/issues/" in url:
            return ReferenceType.ISSUE
        elif ref_type_str == "WEB":
            return ReferenceType.WEB
        return ReferenceType.UNKNOWN


def sync_package_advisories(
    package_name: str,
    db: DatabaseManager,
    client: Optional[OSVClient] = None,
    use_cache: bool = True,
) -> list[Advisory]:
    """Fetch all advisories for a package and persist them in the local database.

    Args:
        package_name: Target Python package name.
        db: DatabaseManager instance.
        client: Optional configured OSVClient (creates default if omitted).
        use_cache: Whether to read/write cache.

    Returns:
        List of ingested Advisory domain models.
    """
    cache_repo = CacheRepository(db)
    osv = client or OSVClient(cache_repo=cache_repo)
    advisories = osv.query_package(package_name, ecosystem="PyPI", use_cache=use_cache)

    adv_repo = AdvisoryRepository(db)
    for adv in advisories:
        adv_repo.save_advisory(adv)
        logger.debug("Persisted advisory %s for package %s", adv.id, package_name)

    logger.info("Synchronized %d advisories for '%s'", len(advisories), package_name)
    return advisories
