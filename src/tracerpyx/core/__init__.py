"""Core foundational models, exceptions, enums, and logging utilities for TracerPyX."""

from tracerpyx.core.enums import (
    ConfidenceLevel,
    ExtractorType,
    ReachabilityStatus,
    ReferenceType,
    ReportFormat,
    ResolutionKind,
    SymbolValidationStatus,
)
from tracerpyx.core.exceptions import (
    AdvisoryCollectionError,
    ConfigurationError,
    DatabaseError,
    DatabaseMigrationError,
    LLMProviderError,
    ManifestParseError,
    ProjectDiscoveryError,
    ReachabilityError,
    SourceParseError,
    SymbolResolutionError,
    TracerPyXError,
)
from tracerpyx.core.logging import configure_logging, get_logger
from tracerpyx.core.models import (
    Advisory,
    AdvisoryReference,
    AffectedPackage,
    CallEdge,
    CallPath,
    CallSite,
    ReachabilityResult,
    ScanReport,
    SourceLocation,
    SymbolEvidence,
    VersionRange,
    VulnerableSymbol,
)

__all__ = [
    # Enums
    "SymbolValidationStatus",
    "ReachabilityStatus",
    "ConfidenceLevel",
    "ResolutionKind",
    "ReferenceType",
    "ExtractorType",
    "ReportFormat",
    # Models
    "SourceLocation",
    "VersionRange",
    "AdvisoryReference",
    "SymbolEvidence",
    "VulnerableSymbol",
    "AffectedPackage",
    "Advisory",
    "CallSite",
    "CallEdge",
    "CallPath",
    "ReachabilityResult",
    "ScanReport",
    # Exceptions
    "TracerPyXError",
    "ConfigurationError",
    "ProjectDiscoveryError",
    "ManifestParseError",
    "SourceParseError",
    "SymbolResolutionError",
    "AdvisoryCollectionError",
    "DatabaseError",
    "DatabaseMigrationError",
    "ReachabilityError",
    "LLMProviderError",
    # Logging
    "configure_logging",
    "get_logger",
]
