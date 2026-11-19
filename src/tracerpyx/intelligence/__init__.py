"""Vulnerability intelligence pipeline for advisory collection and patch analysis."""

from tracerpyx.intelligence.osv_collector import (
    OSVClient,
    sync_package_advisories,
)
from tracerpyx.intelligence.patch_retriever import (
    PatchRetriever,
    fetch_and_cache_advisory_patches,
)
from tracerpyx.intelligence.reference_classifier import (
    ClassifiedReference,
    classify_reference,
    find_fix_references,
)

__all__ = [
    "OSVClient",
    "sync_package_advisories",
    "ClassifiedReference",
    "classify_reference",
    "find_fix_references",
    "PatchRetriever",
    "fetch_and_cache_advisory_patches",
]
