"""Unit tests for TracerPyX core domain models, enums, and exceptions."""

from __future__ import annotations

from dataclasses import FrozenInstanceError
from datetime import datetime

import pytest

from tracerpyx.core import (
    Advisory,
    AdvisoryCollectionError,
    AdvisoryReference,
    AffectedPackage,
    CallEdge,
    CallPath,
    CallSite,
    ConfidenceLevel,
    ExtractorType,
    ReachabilityResult,
    ReachabilityStatus,
    ReferenceType,
    ResolutionKind,
    ScanReport,
    SourceLocation,
    SymbolEvidence,
    SymbolValidationStatus,
    TracerPyXError,
    VersionRange,
    VulnerableSymbol,
)


def test_enums_values_and_types() -> None:
    """Ensure enums serialize and compare to string values properly."""
    assert SymbolValidationStatus.CONFIRMED.value == "CONFIRMED"
    assert ReachabilityStatus.REACHABLE == "REACHABLE"
    assert ConfidenceLevel.HIGH == "HIGH"
    assert ResolutionKind.DIRECT_IMPORT == "DIRECT_IMPORT"
    assert ReferenceType.FIX_COMMIT == "FIX_COMMIT"
    assert ExtractorType.AST_DIFF == "AST_DIFF"


def test_source_location_display() -> None:
    """Test SourceLocation post_init and display formatting."""
    loc_single = SourceLocation(file_path="app/main.py", line_start=15)
    assert loc_single.line_end == 15
    assert loc_single.to_display_string() == "app/main.py:15"

    loc_range = SourceLocation(file_path="app/main.py", line_start=15, line_end=20)
    assert loc_range.to_display_string() == "app/main.py:15-20"


def test_model_immutability() -> None:
    """Ensure frozen dataclasses prevent in-place attribute mutations."""
    loc = SourceLocation(file_path="test.py", line_start=1)
    with pytest.raises((FrozenInstanceError, AttributeError)):
        loc.line_start = 5  # type: ignore[misc]


def test_version_range_display() -> None:
    """Test VersionRange human-readable string representation."""
    vr_full = VersionRange(introduced="1.0.0", fixed="1.5.0")
    assert vr_full.to_display_string() == ">=1.0.0, <1.5.0"

    vr_last = VersionRange(introduced="0", last_affected="2.3.1")
    assert vr_last.to_display_string() == "<=2.3.1"

    vr_all = VersionRange(introduced="0")
    assert vr_all.to_display_string() == "all versions"


def test_vulnerable_symbol_properties() -> None:
    """Test VulnerableSymbol status helper properties."""
    ev = SymbolEvidence(
        commit_url="https://github.com/foo/bar/commit/123",
        commit_sha="123",
        file_path="bar.py",
        line_start=10,
        line_end=15,
        diff_hunk="@@ -10,5 +10,5 @@",
        rationale="Fixes input validation flaw",
    )
    sym_confirmed = VulnerableSymbol(
        symbol_name="bar.validate",
        validation_status=SymbolValidationStatus.CONFIRMED,
        evidence=(ev,),
    )
    assert sym_confirmed.is_confirmed is True
    assert sym_confirmed.is_usable is True

    sym_rejected = VulnerableSymbol(
        symbol_name="bar.test_check",
        validation_status=SymbolValidationStatus.REJECTED,
    )
    assert sym_rejected.is_confirmed is False
    assert sym_rejected.is_usable is False


def test_call_path_chain() -> None:
    """Test CallPath traversal properties and chain generation."""
    loc1 = SourceLocation("main.py", 10)
    loc2 = SourceLocation("services.py", 25)

    edge1 = CallEdge(
        source_fqn="main.main",
        target_fqn="services.checkout",
        location=loc1,
        resolution_kind=ResolutionKind.DIRECT_IMPORT,
    )
    edge2 = CallEdge(
        source_fqn="services.checkout",
        target_fqn="vuln_lib.process",
        location=loc2,
        resolution_kind=ResolutionKind.ATTRIBUTE,
    )

    path = CallPath(edges=(edge1, edge2))
    assert path.length == 2
    assert path.entry_point == "main.main"
    assert path.target == "vuln_lib.process"
    assert path.to_display_chain() == [
        "main.main",
        "services.checkout",
        "vuln_lib.process",
    ]


def test_reachability_result_and_scan_report_serialization() -> None:
    """Test ScanReport aggregation and serialization to dictionary."""
    loc = SourceLocation("app.py", 5)
    edge = CallEdge("app.start", "lib.parse", loc)
    path = CallPath(edges=(edge,))

    res1 = ReachabilityResult(
        advisory_id="GHSA-1234",
        package_name="test-lib",
        installed_version="1.0.0",
        status=ReachabilityStatus.REACHABLE,
        confidence=ConfidenceLevel.HIGH,
        target_symbol="lib.parse",
        paths=(path,),
        rationale="Path found",
    )

    res2 = ReachabilityResult(
        advisory_id="GHSA-5678",
        package_name="other-lib",
        installed_version="2.0.0",
        status=ReachabilityStatus.UNREACHABLE,
        confidence=ConfidenceLevel.HIGH,
        rationale="Unreachable target",
    )

    report = ScanReport(
        project_path="/tmp/my_project",
        scanned_at=datetime(2026, 11, 19, 12, 0, 0),
        results=(res1, res2),
    )

    assert report.total_advisories == 2
    assert report.reachable_count == 1
    assert report.unreachable_count == 1
    assert report.uncertain_count == 0

    data = report.to_dict()
    assert data["summary"]["total"] == 2
    assert data["summary"]["reachable"] == 1
    assert len(data["findings"]) == 2
    assert data["findings"][0]["advisory_id"] == "GHSA-1234"
    assert data["findings"][0]["paths"] == [["app.start", "lib.parse"]]


def test_exception_hierarchy() -> None:
    """Test custom exception formatting and hierarchy."""
    err = AdvisoryCollectionError("Failed to fetch OSV advisory", details={"status_code": 404})
    assert isinstance(err, TracerPyXError)
    assert "Failed to fetch OSV advisory" in str(err)
    assert "status_code" in str(err)
