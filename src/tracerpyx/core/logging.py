"""Centralized logging configuration for TracerPyX."""

from __future__ import annotations

import logging
import sys
from pathlib import Path
from typing import Optional

try:
    from rich.logging import RichHandler
    HAS_RICH = True
except ImportError:  # pragma: no cover
    HAS_RICH = False

_DEFAULT_FORMAT = "%(asctime)s [%(levelname)s] %(name)s: %(message)s"
_DATE_FORMAT = "%Y-%m-%d %H:%M:%S"


def configure_logging(
    level: str = "INFO",
    log_file: Optional[str | Path] = None,
    use_rich: bool = True,
) -> None:
    """Configure the root logger for TracerPyX.

    Args:
        level: Logging level string (e.g. 'DEBUG', 'INFO', 'WARNING', 'ERROR').
        log_file: Optional path to write plain text log output to disk.
        use_rich: Whether to use RichHandler for console output if available.
    """
    numeric_level = getattr(logging, level.upper(), logging.INFO)
    root_logger = logging.getLogger("tracerpyx")
    root_logger.setLevel(numeric_level)

    # Avoid accumulating duplicate handlers if called multiple times
    root_logger.handlers.clear()

    # Console handler
    if use_rich and HAS_RICH:
        console_handler: logging.Handler = RichHandler(
            level=numeric_level,
            show_time=False,
            show_path=False,
            markup=True,
            rich_tracebacks=True,
        )
    else:
        console_handler = logging.StreamHandler(sys.stderr)
        console_handler.setLevel(numeric_level)
        console_handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATE_FORMAT))

    root_logger.addHandler(console_handler)

    # File handler (if requested)
    if log_file:
        file_path = Path(log_file).expanduser().resolve()
        file_path.parent.mkdir(parents=True, exist_ok=True)
        file_handler = logging.FileHandler(file_path, encoding="utf-8")
        file_handler.setLevel(numeric_level)
        file_handler.setFormatter(logging.Formatter(_DEFAULT_FORMAT, datefmt=_DATE_FORMAT))
        root_logger.addHandler(file_handler)


def get_logger(name: str) -> logging.Logger:
    """Retrieve a namespaced logger under the 'tracerpyx' hierarchy.

    Args:
        name: Suffix or dotted path (e.g. 'engine.reachability' or 'cli').

    Returns:
        logging.Logger instance prefixed with 'tracerpyx.'.
    """
    if name.startswith("tracerpyx.") or name == "tracerpyx":
        return logging.getLogger(name)
    return logging.getLogger(f"tracerpyx.{name}")
