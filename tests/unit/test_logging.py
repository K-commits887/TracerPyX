"""Unit tests for TracerPyX logging configuration."""

from __future__ import annotations

import logging
from pathlib import Path

from tracerpyx.core.logging import configure_logging, get_logger


def test_get_logger_prefix() -> None:
    """Ensure get_logger prefixes the name with 'tracerpyx.'."""
    logger = get_logger("engine.reachability")
    assert logger.name == "tracerpyx.engine.reachability"

    # If already prefixed, should not double-prefix
    logger_already_prefixed = get_logger("tracerpyx.discovery")
    assert logger_already_prefixed.name == "tracerpyx.discovery"

    # Root tracerpyx logger
    root_tracerpyx = get_logger("tracerpyx")
    assert root_tracerpyx.name == "tracerpyx"


def test_configure_logging_levels() -> None:
    """Ensure configure_logging sets the correct numeric log level on the root logger."""
    configure_logging(level="DEBUG", use_rich=False)
    root = logging.getLogger("tracerpyx")
    assert root.level == logging.DEBUG

    configure_logging(level="WARNING", use_rich=False)
    assert root.level == logging.WARNING


def test_configure_logging_to_file(tmp_path: Path) -> None:
    """Ensure configure_logging writes log messages to disk when requested."""
    log_file = tmp_path / "logs" / "test.log"
    configure_logging(level="INFO", log_file=log_file, use_rich=False)

    logger = get_logger("test_module")
    test_msg = "Diagnostic test event for file logging"
    logger.info(test_msg)

    # Flush all handlers
    for handler in logging.getLogger("tracerpyx").handlers:
        handler.flush()

    assert log_file.exists()
    content = log_file.read_text(encoding="utf-8")
    assert test_msg in content
    assert "[INFO]" in content
