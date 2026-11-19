"""Reference URL classifier and commit discovery for security advisories."""

from __future__ import annotations

import re
from dataclasses import dataclass
from typing import Optional
from urllib.parse import urlparse

from tracerpyx.core.enums import ConfidenceLevel, ReferenceType
from tracerpyx.core.models import Advisory, AdvisoryReference

# Regular expressions for Git platforms and reference types
_GITHUB_COMMIT_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/commit/(?P<sha>[0-9a-fA-F]{7,40})(?:\.patch|\.diff)?/?$",
    re.IGNORECASE,
)
_GITHUB_PR_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/pull/(?P<pr>\d+)(?:\.patch|\.diff)?(?:/commits/(?P<sha>[0-9a-fA-F]{7,40}))?/?$",
    re.IGNORECASE,
)
_GITHUB_ISSUE_RE = re.compile(
    r"^https?://(?:www\.)?github\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/issues/(?P<issue>\d+)/?$",
    re.IGNORECASE,
)
_GITLAB_COMMIT_RE = re.compile(
    r"^https?://(?:www\.)?gitlab\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/-(?:/commit/|/commits/)(?P<sha>[0-9a-fA-F]{7,40})(?:\.patch|\.diff)?/?$",
    re.IGNORECASE,
)
_GITLAB_MR_RE = re.compile(
    r"^https?://(?:www\.)?gitlab\.com/(?P<owner>[^/]+)/(?P<repo>[^/]+)/-(?:/merge_requests/)(?P<mr>\d+)/?$",
    re.IGNORECASE,
)
_GENERIC_COMMIT_RE = re.compile(
    r"[?&;](?:commit|id|h)=(?P<sha>[0-9a-fA-F]{7,40})",
    re.IGNORECASE,
)
_ADVISORY_HOSTS = {
    "nvd.nist.gov",
    "cve.org",
    "cve.mitre.org",
    "osv.dev",
    "security.snyk.io",
    "advisories.github.com",
}


@dataclass(frozen=True)
class ClassifiedReference:
    """Classified external reference containing structured metadata."""

    original_url: str
    reference_type: ReferenceType
    platform: Optional[str] = None  # "github", "gitlab", "cgit", etc.
    repo_owner: Optional[str] = None
    repo_name: Optional[str] = None
    commit_sha: Optional[str] = None
    pr_number: Optional[int] = None
    patch_url: Optional[str] = None
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH

    @property
    def is_fix(self) -> bool:
        """Whether this reference points to an explicit code fix (commit or PR)."""
        return self.reference_type in (ReferenceType.FIX_COMMIT, ReferenceType.PULL_REQUEST)


def classify_reference(url: str, advisory_tag: Optional[str] = None) -> ClassifiedReference:
    """Classify a reference URL and extract repository/commit coordinates.

    Args:
        url: Raw reference URL string.
        advisory_tag: Optional advisory type tag (e.g. 'FIX', 'ADVISORY', 'REPORT', 'WEB').

    Returns:
        ClassifiedReference with normalized type, platform, coordinates, and patch download link.
    """
    clean_url = url.strip()
    parsed = urlparse(clean_url)
    hostname = (parsed.hostname or "").lower()

    # 1. GitHub Commit
    m_gh_commit = _GITHUB_COMMIT_RE.match(clean_url)
    if m_gh_commit:
        owner = m_gh_commit.group("owner")
        repo = m_gh_commit.group("repo")
        sha = m_gh_commit.group("sha")
        patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.FIX_COMMIT,
            platform="github",
            repo_owner=owner,
            repo_name=repo,
            commit_sha=sha,
            patch_url=patch_url,
            confidence=ConfidenceLevel.HIGH,
        )

    # 2. GitHub Pull Request (or specific commit in PR)
    m_gh_pr = _GITHUB_PR_RE.match(clean_url)
    if m_gh_pr:
        owner = m_gh_pr.group("owner")
        repo = m_gh_pr.group("repo")
        pr_num = int(m_gh_pr.group("pr"))
        sha = m_gh_pr.group("sha")
        if sha:
            patch_url = f"https://github.com/{owner}/{repo}/commit/{sha}.patch"
            return ClassifiedReference(
                original_url=clean_url,
                reference_type=ReferenceType.FIX_COMMIT,
                platform="github",
                repo_owner=owner,
                repo_name=repo,
                commit_sha=sha,
                pr_number=pr_num,
                patch_url=patch_url,
                confidence=ConfidenceLevel.HIGH,
            )
        else:
            patch_url = f"https://github.com/{owner}/{repo}/pull/{pr_num}.patch"
            return ClassifiedReference(
                original_url=clean_url,
                reference_type=ReferenceType.PULL_REQUEST,
                platform="github",
                repo_owner=owner,
                repo_name=repo,
                pr_number=pr_num,
                patch_url=patch_url,
                confidence=ConfidenceLevel.MEDIUM,
            )

    # 3. GitHub Issue
    m_gh_issue = _GITHUB_ISSUE_RE.match(clean_url)
    if m_gh_issue:
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.ISSUE,
            platform="github",
            repo_owner=m_gh_issue.group("owner"),
            repo_name=m_gh_issue.group("repo"),
            confidence=ConfidenceLevel.HIGH,
        )

    # 4. GitLab Commit
    m_gl_commit = _GITLAB_COMMIT_RE.match(clean_url)
    if m_gl_commit:
        owner = m_gl_commit.group("owner")
        repo = m_gl_commit.group("repo")
        sha = m_gl_commit.group("sha")
        patch_url = f"https://gitlab.com/{owner}/{repo}/-/commit/{sha}.diff"
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.FIX_COMMIT,
            platform="gitlab",
            repo_owner=owner,
            repo_name=repo,
            commit_sha=sha,
            patch_url=patch_url,
            confidence=ConfidenceLevel.HIGH,
        )

    # 5. GitLab Merge Request
    m_gl_mr = _GITLAB_MR_RE.match(clean_url)
    if m_gl_mr:
        owner = m_gl_mr.group("owner")
        repo = m_gl_mr.group("repo")
        mr_num = int(m_gl_mr.group("mr"))
        patch_url = f"https://gitlab.com/{owner}/{repo}/-/merge_requests/{mr_num}.diff"
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.PULL_REQUEST,
            platform="gitlab",
            repo_owner=owner,
            repo_name=repo,
            pr_number=mr_num,
            patch_url=patch_url,
            confidence=ConfidenceLevel.MEDIUM,
        )

    # 6. Generic Git web viewers (cgit, gitweb with ?id=<sha> or ?h=<sha>)
    m_generic = _GENERIC_COMMIT_RE.search(clean_url)
    if m_generic:
        sha = m_generic.group("sha")
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.FIX_COMMIT,
            platform="cgit",
            commit_sha=sha,
            confidence=ConfidenceLevel.MEDIUM,
        )

    # 7. Known Advisory Databases
    if hostname in _ADVISORY_HOSTS or "/advisories/" in clean_url or "/vuln/" in clean_url:
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.ADVISORY,
            confidence=ConfidenceLevel.HIGH,
        )

    # 8. Web documentation, releases, changelogs
    parsed_path = parsed.path.lower()
    if any(segment in parsed_path for segment in ("/releases", "/blob/", "/tree/", "/wiki/", "/tags", "/changelog")):
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.WEB,
            confidence=ConfidenceLevel.MEDIUM,
        )

    # 9. Tag-guided fallback
    tag = (advisory_tag or "").upper()
    if tag == "FIX":
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.FIX_COMMIT,
            confidence=ConfidenceLevel.LOW,
        )
    elif tag in ("ADVISORY", "REPORT"):
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.ADVISORY,
            confidence=ConfidenceLevel.HIGH,
        )
    elif tag == "WEB" or any(clean_url.endswith(ext) for ext in (".html", ".md", ".rst", "/")):
        return ClassifiedReference(
            original_url=clean_url,
            reference_type=ReferenceType.WEB,
            confidence=ConfidenceLevel.LOW,
        )

    return ClassifiedReference(
        original_url=clean_url,
        reference_type=ReferenceType.UNKNOWN,
        confidence=ConfidenceLevel.UNKNOWN,
    )


def find_fix_references(advisory: Advisory) -> list[ClassifiedReference]:
    """Inspect all references in an Advisory and return only prioritized fix references.

    Priority order:
    1. Direct FIX_COMMIT with extracted commit_sha
    2. PULL_REQUEST with patch_url
    3. Low-confidence references tagged with FIX
    """
    classified = [classify_reference(ref.url) for ref in advisory.references]

    # Filter to fixes
    fixes = [c for c in classified if c.is_fix]

    # Sort so direct commits with SHA are prioritized first
    fixes.sort(key=lambda c: (0 if c.commit_sha else 1, 0 if c.reference_type == ReferenceType.FIX_COMMIT else 1))
    return fixes
