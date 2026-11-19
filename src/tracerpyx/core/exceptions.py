"""Custom exception hierarchy for TracerPyX."""

from __future__ import annotations


class TracerPyXError(Exception):
    """Base exception for all errors raised by TracerPyX."""

    def __init__(self, message: str, details: dict | None = None) -> None:
        super().__init__(message)
        self.message = message
        self.details = details or {}

    def __str__(self) -> str:
        if self.details:
            return f"{self.message} (details: {self.details})"
        return self.message


class ConfigurationError(TracerPyXError):
    """Raised when configuration, CLI flags, or environment variables are invalid."""


class ProjectDiscoveryError(TracerPyXError):
    """Raised when discovering project source files or environments fails."""


class ManifestParseError(TracerPyXError):
    """Raised when parsing requirements.txt, pyproject.toml, or lockfiles fails."""


class SourceParseError(TracerPyXError):
    """Raised when a Python source file cannot be parsed into an AST."""


class SymbolResolutionError(TracerPyXError):
    """Raised when symbol extraction or scoping fails unexpectedly."""


class AdvisoryCollectionError(TracerPyXError):
    """Raised when querying, downloading, or parsing vulnerability advisories fails."""


class DatabaseError(TracerPyXError):
    """Raised when SQLite operations, migrations, or transactions fail."""


class DatabaseMigrationError(DatabaseError):
    """Raised when applying database schema migrations fails."""


class ReachabilityError(TracerPyXError):
    """Raised when graph traversal or reachability evaluation encounters an invalid state."""


class LLMProviderError(TracerPyXError):
    """Raised when an external or mock LLM provider fails to generate a valid response."""
