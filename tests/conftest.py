"""Shared pytest fixtures for TracerPyX test suites."""

from __future__ import annotations

import logging
from pathlib import Path
from typing import Generator

import pytest

from tracerpyx.core.logging import configure_logging


@pytest.fixture(autouse=True)
def reset_logging() -> Generator[None, None, None]:
    """Ensure logging is reset to a clean state after each test."""
    yield
    configure_logging(level="WARNING", use_rich=False)
    # Clean up any residual handlers
    root = logging.getLogger("tracerpyx")
    root.handlers.clear()


@pytest.fixture
def temp_project_dir(tmp_path: Path) -> Path:
    """Provide a temporary directory structure mimicking a simple Python project."""
    project_dir = tmp_path / "sample_project"
    project_dir.mkdir(parents=True, exist_ok=True)
    
    # Create simple main.py
    main_file = project_dir / "main.py"
    main_file.write_text(
        "def main():\n    print('Hello TracerPyX')\n\nif __name__ == '__main__':\n    main()\n",
        encoding="utf-8",
    )
    
    # Create simple requirements.txt
    req_file = project_dir / "requirements.txt"
    req_file.write_text("requests==2.31.0\n", encoding="utf-8")
    
    return project_dir
