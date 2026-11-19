"""Immutable domain models for TracerPyX."""

from __future__ import annotations

from dataclasses import asdict, dataclass, field
from datetime import datetime
from typing import Any, Optional

from tracerpyx.core.enums import (
    ConfidenceLevel,
    ExtractorType,
    ReachabilityStatus,
    ReferenceType,
    ResolutionKind,
    SymbolValidationStatus,
)


@dataclass(frozen=True)
class SourceLocation:
    """Exact source code location span."""

    file_path: str
    line_start: int
    line_end: int = 0
    col_start: int = 0
    col_end: int = 0

    def __post_init__(self) -> None:
        if self.line_end <= 0:
            object.__setattr__(self, "line_end", self.line_start)

    def to_display_string(self) -> str:
        """Formatted display string e.g. 'app/services.py:42'."""
        if self.line_start == self.line_end or self.line_end == 0:
            return f"{self.file_path}:{self.line_start}"
        return f"{self.file_path}:{self.line_start}-{self.line_end}"


@dataclass(frozen=True)
class VersionRange:
    """Represents an affected version interval according to OSV/OpenVEX semantics."""

    introduced: str = "0"
    fixed: Optional[str] = None
    last_affected: Optional[str] = None

    def to_display_string(self) -> str:
        """Human-readable representation of the version constraint."""
        parts = []
        if self.introduced and self.introduced != "0":
            parts.append(f">={self.introduced}")
        if self.fixed:
            parts.append(f"<{self.fixed}")
        elif self.last_affected:
            parts.append(f"<={self.last_affected}")
        return ", ".join(parts) if parts else "all versions"


@dataclass(frozen=True)
class AdvisoryReference:
    """Classified external reference URL attached to an advisory."""

    url: str
    reference_type: ReferenceType = ReferenceType.UNKNOWN
    commit_sha: Optional[str] = None


@dataclass(frozen=True)
class SymbolEvidence:
    """Concrete evidence tying a candidate symbol to a fix commit or diff."""

    commit_url: str
    commit_sha: str
    file_path: str
    line_start: int
    line_end: int
    diff_hunk: str
    rationale: str
    extractor: ExtractorType = ExtractorType.AST_DIFF


@dataclass(frozen=True)
class VulnerableSymbol:
    """Identified function, method, or class within a package containing a flaw."""

    symbol_name: str
    symbol_type: str = "FUNCTION"  # FUNCTION, METHOD, CLASS, MODULE
    validation_status: SymbolValidationStatus = SymbolValidationStatus.CANDIDATE
    confidence: ConfidenceLevel = ConfidenceLevel.MEDIUM
    evidence: tuple[SymbolEvidence, ...] = field(default_factory=tuple)

    @property
    def is_confirmed(self) -> bool:
        return self.validation_status == SymbolValidationStatus.CONFIRMED

    @property
    def is_usable(self) -> bool:
        return self.validation_status in (
            SymbolValidationStatus.CONFIRMED,
            SymbolValidationStatus.CANDIDATE,
        )


@dataclass(frozen=True)
class AffectedPackage:
    """Package affected by an advisory within a specific ecosystem."""

    package_name: str
    ecosystem: str = "PyPI"
    version_ranges: tuple[VersionRange, ...] = field(default_factory=tuple)
    symbols: tuple[VulnerableSymbol, ...] = field(default_factory=tuple)


@dataclass(frozen=True)
class Advisory:
    """Canonical representation of a vulnerability advisory."""

    id: str  # GHSA-xxx, PYSEC-xxx, or CVE-xxx
    source: str  # OSV, GHSA, PYPA
    title: str = ""
    details: str = ""
    aliases: tuple[str, ...] = field(default_factory=tuple)
    published_at: Optional[datetime] = None
    modified_at: Optional[datetime] = None
    affected_packages: tuple[AffectedPackage, ...] = field(default_factory=tuple)
    references: tuple[AdvisoryReference, ...] = field(default_factory=tuple)
    raw_payload: str = ""


@dataclass(frozen=True)
class CallSite:
    """Raw call occurrence extracted from AST before resolution."""

    caller_fqn: str
    receiver: Optional[str]
    function_name: str
    location: SourceLocation


@dataclass(frozen=True)
class CallEdge:
    """Directed edge in the call graph connecting caller and callee."""

    source_fqn: str
    target_fqn: str
    location: SourceLocation
    resolution_kind: ResolutionKind = ResolutionKind.DIRECT_IMPORT
    confidence: ConfidenceLevel = ConfidenceLevel.HIGH


@dataclass(frozen=True)
class CallPath:
    """Ordered sequence of call edges leading from an entry point to a target."""

    edges: tuple[CallEdge, ...] = field(default_factory=tuple)

    @property
    def entry_point(self) -> Optional[str]:
        return self.edges[0].source_fqn if self.edges else None

    @property
    def target(self) -> Optional[str]:
        return self.edges[-1].target_fqn if self.edges else None

    @property
    def length(self) -> int:
        return len(self.edges)

    def to_display_chain(self) -> list[str]:
        """Returns sequence of node names e.g. ['main.main', 'services.run', 'lib.vuln']."""
        if not self.edges:
            return []
        chain = [self.edges[0].source_fqn]
        for edge in self.edges:
            chain.append(edge.target_fqn)
        return chain


@dataclass(frozen=True)
class ReachabilityResult:
    """The reachability finding for a specific package and advisory."""

    advisory_id: str
    package_name: str
    installed_version: str
    status: ReachabilityStatus
    confidence: ConfidenceLevel
    target_symbol: Optional[str] = None
    paths: tuple[CallPath, ...] = field(default_factory=tuple)
    rationale: str = ""
    limitations: tuple[str, ...] = field(default_factory=tuple)

    def to_dict(self) -> dict[str, Any]:
        """Serialize finding to dictionary format."""
        return {
            "advisory_id": self.advisory_id,
            "package_name": self.package_name,
            "installed_version": self.installed_version,
            "status": self.status.value,
            "confidence": self.confidence.value,
            "target_symbol": self.target_symbol,
            "paths": [path.to_display_chain() for path in self.paths],
            "rationale": self.rationale,
            "limitations": list(self.limitations),
        }


@dataclass(frozen=True)
class ScanReport:
    """Top-level scan outcome for a project."""

    project_path: str
    scanned_at: datetime
    results: tuple[ReachabilityResult, ...] = field(default_factory=tuple)

    @property
    def total_advisories(self) -> int:
        return len(self.results)

    @property
    def reachable_count(self) -> int:
        return sum(1 for r in self.results if r.status == ReachabilityStatus.REACHABLE)

    @property
    def unreachable_count(self) -> int:
        return sum(1 for r in self.results if r.status == ReachabilityStatus.UNREACHABLE)

    @property
    def uncertain_count(self) -> int:
        return sum(1 for r in self.results if r.status == ReachabilityStatus.UNCERTAIN)

    def to_dict(self) -> dict[str, Any]:
        return {
            "project_path": self.project_path,
            "scanned_at": self.scanned_at.isoformat(),
            "summary": {
                "total": self.total_advisories,
                "reachable": self.reachable_count,
                "unreachable": self.unreachable_count,
                "uncertain": self.uncertain_count,
            },
            "findings": [res.to_dict() for res in self.results],
        }
