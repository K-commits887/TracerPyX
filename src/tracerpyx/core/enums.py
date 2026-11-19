"""Core enumeration types for TracerPyX."""

from __future__ import annotations

from enum import Enum


class SymbolValidationStatus(str, Enum):
    """Validation status for candidate vulnerable symbols."""

    CONFIRMED = "CONFIRMED"
    """Explicitly verified in pre-patch AST or vendor advisory bulletin."""

    CANDIDATE = "CANDIDATE"
    """Inferred from commit diffs or suggested by heuristics, awaiting full verification."""

    PACKAGE_ONLY = "PACKAGE_ONLY"
    """Affected version range is known, but no specific symbol exists or diff is non-Python."""

    UNKNOWN = "UNKNOWN"
    """Advisory references are ambiguous, missing, or unparseable."""

    REJECTED = "REJECTED"
    """Determined to be unrelated, a newly added fix function, test fixture, or nonexistent."""


class ReachabilityStatus(str, Enum):
    """Final reachability verdict issued for an advisory."""

    REACHABLE = "REACHABLE"
    """A verified call path exists from an application entry point to the vulnerable symbol."""

    UNREACHABLE = "UNREACHABLE"
    """Complete graph analysis proves no execution path can reach the vulnerable symbol."""

    UNCERTAIN = "UNCERTAIN"
    """Evidence is insufficient (unknown symbol, unresolved dynamic calls, or opaque boundaries)."""


class ConfidenceLevel(str, Enum):
    """Confidence grade attached to call edges, symbols, and reachability paths."""

    HIGH = "HIGH"
    """Direct syntactic evidence with zero ambiguity (e.g. direct import and call)."""

    MEDIUM = "MEDIUM"
    """Inferred or resolved via class inheritance or standard attribute resolution."""

    LOW = "LOW"
    """Resolved via dynamic heuristics, constant propagation, or LLM estimation."""

    UNKNOWN = "UNKNOWN"
    """Insufficient context to assign confidence."""


class ResolutionKind(str, Enum):
    """Method utilized by symbol resolver to link a call site to a definition."""

    DIRECT_IMPORT = "DIRECT_IMPORT"
    """Direct import: 'from mod import func' followed by 'func()'."""

    ALIASED_IMPORT = "ALIASED_IMPORT"
    """Aliased import: 'import mod as m' or 'from mod import func as f'."""

    ATTRIBUTE = "ATTRIBUTE"
    """Module attribute call: 'mod.func()'."""

    METHOD_DISPATCH = "METHOD_DISPATCH"
    """Method invocation resolved through class definition or single inheritance."""

    DYNAMIC_RESOLVED = "DYNAMIC_RESOLVED"
    """Resolved through constant propagation or heuristic suggestion."""

    UNRESOLVED = "UNRESOLVED"
    """Could not be deterministically resolved at static analysis time."""


class ReferenceType(str, Enum):
    """Classification of an advisory reference URL."""

    FIX_COMMIT = "FIX_COMMIT"
    """Direct link to a Git commit that resolves the vulnerability."""

    PULL_REQUEST = "PULL_REQUEST"
    """Link to an upstream pull request."""

    ISSUE = "ISSUE"
    """Link to an issue tracker report."""

    ADVISORY = "ADVISORY"
    """Vendor, CVE, or GHSA bulletin."""

    WEB = "WEB"
    """General documentation, blog post, or release notes."""

    UNKNOWN = "UNKNOWN"
    """Unclassified URL."""


class ExtractorType(str, Enum):
    """Source method responsible for extracting a vulnerable symbol."""

    AST_DIFF = "AST_DIFF"
    """Extracted deterministically by AST diff analysis on the fix commit."""

    EXPLICIT_ADVISORY = "EXPLICIT_ADVISORY"
    """Directly documented in advisory summary or CVE description."""

    LLM_ASSISTED = "LLM_ASSISTED"
    """Suggested by an LLM and subsequently validated against AST."""

    MANUAL = "MANUAL"
    """Human analyst curated mapping."""


class ReportFormat(str, Enum):
    """Supported output formats for scan reports."""

    TERMINAL = "terminal"
    JSON = "json"
    OPENVEX = "openvex"
