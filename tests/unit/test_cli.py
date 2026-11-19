"""Unit tests for TracerPyX CLI commands and argument parser."""

from __future__ import annotations

from pathlib import Path
import pytest

from tracerpyx import __version__
from tracerpyx.cli import build_parser, main


def test_cli_version(capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure --version displays current version and terminates."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--version"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert f"tracerpyx {__version__}" in captured.out


def test_cli_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure --help displays usage information and exit code is 0."""
    with pytest.raises(SystemExit) as exc_info:
        main(["--help"])
    assert exc_info.value.code == 0
    captured = capsys.readouterr()
    assert "TracerPyX: Static Vulnerability Reachability Analyzer" in captured.out
    assert "scan" in captured.out
    assert "advisory" in captured.out
    assert "db" in captured.out


def test_cli_no_args_shows_help(capsys: pytest.CaptureFixture[str]) -> None:
    """Calling main without arguments should display help and return 0."""
    ret = main([])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Available TracerPyX commands" in captured.out


def test_scan_command_valid_project(temp_project_dir: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure scan command succeeds on an existing project directory."""
    ret = main(["scan", str(temp_project_dir), "-e", "main:main", "-f", "json"])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Scan placeholder" in captured.out


def test_scan_command_missing_project(tmp_path: Path) -> None:
    """Ensure scan command returns error code 2 when project directory does not exist."""
    non_existent = tmp_path / "does_not_exist"
    ret = main(["scan", str(non_existent)])
    assert ret == 2


def test_advisory_lookup_by_package(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure advisory lookup by package runs successfully."""
    from tracerpyx.core.models import Advisory, AffectedPackage
    from tracerpyx.db import AdvisoryRepository, DatabaseManager, run_migrations

    db_path = str(tmp_path / "adv_test.db")
    db = DatabaseManager(db_path)
    run_migrations(db)
    adv_repo = AdvisoryRepository(db)
    pkg = AffectedPackage(package_name="requests")
    adv = Advisory(id="GHSA-test-1", source="OSV", title="Test flaw", affected_packages=(pkg,))
    adv_repo.save_advisory(adv)
    db.close()

    ret = main(["advisory", "lookup", "-p", "requests", "--db-path", db_path])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Found 1 advisory(s) for package 'requests'" in captured.out
    assert "GHSA-test-1" in captured.out


def test_advisory_lookup_by_id(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure advisory lookup by advisory ID runs successfully."""
    from tracerpyx.core.models import Advisory
    from tracerpyx.db import AdvisoryRepository, DatabaseManager, run_migrations

    db_path = str(tmp_path / "adv_test.db")
    db = DatabaseManager(db_path)
    run_migrations(db)
    adv_repo = AdvisoryRepository(db)
    adv = Advisory(id="GHSA-j8r2-6x86-q33q", source="GHSA", title="Requests Header Leak")
    adv_repo.save_advisory(adv)
    db.close()

    ret = main(["advisory", "lookup", "-i", "GHSA-j8r2-6x86-q33q", "--db-path", db_path])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Advisory: [GHSA-j8r2-6x86-q33q]" in captured.out
    assert "Requests Header Leak" in captured.out


def test_advisory_sync(tmp_path: Path, monkeypatch: pytest.MonkeyPatch, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure advisory sync runs successfully when mocked."""
    import tracerpyx.cli
    from tracerpyx.core.models import Advisory

    db_path = str(tmp_path / "sync_test.db")

    def mock_sync(package_name: str, db: object) -> list[Advisory]:
        return [Advisory(id="GHSA-mock-1", source="OSV", title="Mock Vulnerability")]

    monkeypatch.setattr("tracerpyx.intelligence.sync_package_advisories", mock_sync)

    ret = main(["advisory", "sync", "-p", "flask", "--db-path", db_path])
    assert ret == 0
    captured = capsys.readouterr()
    assert "Successfully synchronized 1 advisory(s) for 'flask'" in captured.out


def test_db_subcommands(tmp_path: Path, capsys: pytest.CaptureFixture[str]) -> None:
    """Ensure db status, migrate, and clear-cache subcommands execute."""
    db_file = str(tmp_path / "test.db")
    for action in ["status", "migrate", "clear-cache"]:
        ret = main(["db", action, "--db-path", db_file])
        assert ret == 0
    captured = capsys.readouterr()
    assert "TracerPyX Database" in captured.out
    assert "Successfully applied migration" in captured.out
    assert "Cleared 0 item(s)" in captured.out


def test_logging_flags_configuration(tmp_path: Path) -> None:
    """Ensure verbose and quiet flags adjust logging without crashing."""
    db_file = str(tmp_path / "logging_test.db")
    assert main(["-v", "db", "status", "--db-path", db_file]) == 0
    assert main(["-q", "db", "status", "--db-path", db_file]) == 0
