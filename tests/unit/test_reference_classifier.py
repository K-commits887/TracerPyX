"""Unit tests for advisory reference classification and fix commit discovery."""

from __future__ import annotations

import pytest

from tracerpyx.core.enums import ConfidenceLevel, ReferenceType
from tracerpyx.core.models import Advisory, AdvisoryReference
from tracerpyx.intelligence.reference_classifier import (
    ClassifiedReference,
    classify_reference,
    find_fix_references,
)


@pytest.mark.parametrize(
    "url, expected_type, expected_platform, expected_sha, expected_patch_url",
    [
        # Standard GitHub commit
        (
            "https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702",
            ReferenceType.FIX_COMMIT,
            "github",
            "7492dc4879e37fc361099b2447990db207567702",
            "https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702.patch",
        ),
        # GitHub commit with short SHA and trailing slash
        (
            "https://github.com/pallets/flask/commit/abc1234/",
            ReferenceType.FIX_COMMIT,
            "github",
            "abc1234",
            "https://github.com/pallets/flask/commit/abc1234.patch",
        ),
        # GitHub commit ending with .patch
        (
            "https://github.com/urllib3/urllib3/commit/b830da76.patch",
            ReferenceType.FIX_COMMIT,
            "github",
            "b830da76",
            "https://github.com/urllib3/urllib3/commit/b830da76.patch",
        ),
        # GitHub PR with specific commit
        (
            "https://github.com/psf/requests/pull/6444/commits/7492dc4879e37fc361099b2447990db207567702",
            ReferenceType.FIX_COMMIT,
            "github",
            "7492dc4879e37fc361099b2447990db207567702",
            "https://github.com/psf/requests/commit/7492dc4879e37fc361099b2447990db207567702.patch",
        ),
        # GitHub PR
        (
            "https://github.com/psf/requests/pull/6444",
            ReferenceType.PULL_REQUEST,
            "github",
            None,
            "https://github.com/psf/requests/pull/6444.patch",
        ),
        # GitLab Commit
        (
            "https://gitlab.com/group/project/-/commit/1234567890abcdef",
            ReferenceType.FIX_COMMIT,
            "gitlab",
            "1234567890abcdef",
            "https://gitlab.com/group/project/-/commit/1234567890abcdef.diff",
        ),
        # GitLab Merge Request
        (
            "https://gitlab.com/group/project/-/merge_requests/42",
            ReferenceType.PULL_REQUEST,
            "gitlab",
            None,
            "https://gitlab.com/group/project/-/merge_requests/42.diff",
        ),
        # Generic CGit with id query parameter
        (
            "https://git.kernel.org/pub/scm/linux/kernel/git/torvalds/linux.git/commit/?id=a1b2c3d4e5f67890",
            ReferenceType.FIX_COMMIT,
            "cgit",
            "a1b2c3d4e5f67890",
            None,
        ),
        # GitHub Issue
        (
            "https://github.com/pallets/werkzeug/issues/1234",
            ReferenceType.ISSUE,
            "github",
            None,
            None,
        ),
        # Advisory Database: NVD
        (
            "https://nvd.nist.gov/vuln/detail/CVE-2023-32681",
            ReferenceType.ADVISORY,
            None,
            None,
            None,
        ),
        # Advisory Database: OSV
        (
            "https://osv.dev/vulnerability/GHSA-j8r2-6x86-q33q",
            ReferenceType.ADVISORY,
            None,
            None,
            None,
        ),
        # Web documentation / changelog
        (
            "https://github.com/psf/requests/releases/tag/v2.31.0",
            ReferenceType.WEB,
            None,
            None,
            None,
        ),
    ],
)
def test_classify_reference_patterns(
    url: str,
    expected_type: ReferenceType,
    expected_platform: str | None,
    expected_sha: str | None,
    expected_patch_url: str | None,
) -> None:
    """Test classification and entity extraction across varied real-world reference URLs."""
    res = classify_reference(url)
    assert res.reference_type == expected_type
    assert res.platform == expected_platform
    assert res.commit_sha == expected_sha
    assert res.patch_url == expected_patch_url


def test_classify_reference_tag_fallback() -> None:
    """Ensure advisory_tag guides classification when URL structure is generic."""
    # Tag = FIX
    ref_fix = classify_reference("https://example.com/some/patch/info", advisory_tag="FIX")
    assert ref_fix.reference_type == ReferenceType.FIX_COMMIT
    assert ref_fix.confidence == ConfidenceLevel.LOW

    # Tag = ADVISORY
    ref_adv = classify_reference("https://example.com/security/note", advisory_tag="ADVISORY")
    assert ref_adv.reference_type == ReferenceType.ADVISORY

    # Completely unknown
    ref_unk = classify_reference("https://example.com/unrelated")
    assert ref_unk.reference_type == ReferenceType.UNKNOWN


def test_find_fix_references_priority() -> None:
    """Ensure find_fix_references filters out non-code links and prioritizes direct commits."""
    advisory = Advisory(
        id="GHSA-test-1",
        source="OSV",
        references=(
            AdvisoryReference(url="https://nvd.nist.gov/vuln/detail/CVE-123", reference_type=ReferenceType.ADVISORY),
            AdvisoryReference(url="https://github.com/org/repo/pull/10", reference_type=ReferenceType.PULL_REQUEST),
            AdvisoryReference(
                url="https://github.com/org/repo/commit/abcdef1234567890",
                reference_type=ReferenceType.FIX_COMMIT,
                commit_sha="abcdef1234567890",
            ),
            AdvisoryReference(url="https://example.com/blog/security-news", reference_type=ReferenceType.WEB),
        ),
    )

    fixes = find_fix_references(advisory)
    assert len(fixes) == 2

    # First one must be the direct commit with SHA
    assert fixes[0].reference_type == ReferenceType.FIX_COMMIT
    assert fixes[0].commit_sha == "abcdef1234567890"

    # Second one is the PR
    assert fixes[1].reference_type == ReferenceType.PULL_REQUEST
    assert fixes[1].pr_number == 10
