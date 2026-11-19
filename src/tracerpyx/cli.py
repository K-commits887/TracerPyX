"""Command-Line Interface (CLI) for TracerPyX."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path
from typing import Sequence

from tracerpyx import __version__
from tracerpyx.core.logging import configure_logging, get_logger

logger = get_logger("cli")


def _cmd_scan(args: argparse.Namespace) -> int:
    """Handler for the 'scan' subcommand."""
    project_path = Path(args.project_path).resolve()
    logger.info("Initiating scan on project directory: %s", project_path)

    if not project_path.exists():
        logger.error("Project path does not exist: %s", project_path)
        return 2

    # Placeholder for Stage 10-14 integration
    logger.info("Scan configuration: format=%s, entry_points=%s", args.format, args.entry_point)
    print(f"TracerPyX v{__version__} — Scan placeholder for {project_path}")
    return 0


def _cmd_advisory(args: argparse.Namespace) -> int:
    """Handler for the 'advisory' subcommand."""
    action = getattr(args, "advisory_action", None)
    if action == "lookup":
        target = args.package or args.id
        if not target:
            logger.error("Must specify either --package or --id for lookup.")
            return 2
        logger.info("Looking up advisories for: %s", target)
        print(f"Advisory lookup placeholder for: {target}")
        return 0
    elif action == "sync":
        logger.info("Syncing advisories for package: %s", args.package)
        print(f"Advisory sync placeholder for: {args.package}")
        return 0
    else:
        logger.error("No valid advisory action specified. Use --help.")
        return 2


def _cmd_db(args: argparse.Namespace) -> int:
    """Handler for the 'db' subcommand."""
    action = getattr(args, "db_action", None)
    db_path = Path(args.db_path).expanduser().resolve()
    logger.info("Database command '%s' targeting: %s", action, db_path)

    if action == "status":
        print(f"TracerPyX Database: {db_path} (exists={db_path.exists()})")
        return 0
    elif action == "migrate":
        print(f"Running migrations on: {db_path}")
        return 0
    elif action == "clear-cache":
        print(f"Clearing cache on: {db_path}")
        return 0
    else:
        logger.error("No valid db action specified. Use --help.")
        return 2


def build_parser() -> argparse.ArgumentParser:
    """Construct and configure the command-line argument parser."""
    parser = argparse.ArgumentParser(
        prog="tracerpyx",
        description="TracerPyX: Static Vulnerability Reachability Analyzer for Python Dependencies",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    parser.add_argument(
        "--version",
        action="version",
        version=f"%(prog)s {__version__}",
    )
    parser.add_argument(
        "-v", "--verbose",
        action="store_true",
        help="Enable debug-level logging output.",
    )
    parser.add_argument(
        "-q", "--quiet",
        action="store_true",
        help="Suppress informational output; show warnings and errors only.",
    )
    parser.add_argument(
        "--log-file",
        metavar="PATH",
        type=str,
        default=None,
        help="Optional path to write log output to disk.",
    )

    subparsers = parser.add_subparsers(
        dest="command",
        title="commands",
        description="Available TracerPyX commands",
    )

    # 1. 'scan' subcommand
    scan_parser = subparsers.add_parser(
        "scan",
        help="Scan a Python project for reachable dependency vulnerabilities.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    scan_parser.add_argument(
        "project_path",
        nargs="?",
        default=".",
        help="Path to the target Python project root directory.",
    )
    scan_parser.add_argument(
        "-e", "--entry-point",
        action="append",
        default=[],
        help="Explicit application entry point in 'module:function' format (can be repeated).",
    )
    scan_parser.add_argument(
        "--db-path",
        default="~/.tracerpyx/tracerpyx.db",
        help="Path to SQLite database storing advisories and vulnerable symbols.",
    )
    scan_parser.add_argument(
        "-f", "--format",
        choices=["terminal", "json", "openvex"],
        default="terminal",
        help="Output report format.",
    )
    scan_parser.add_argument(
        "-o", "--output",
        default=None,
        help="Path to write the report file (defaults to standard output).",
    )
    scan_parser.set_defaults(handler=_cmd_scan)

    # 2. 'advisory' subcommand
    adv_parser = subparsers.add_parser(
        "advisory",
        help="Query or synchronize vulnerability advisories.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    adv_subparsers = adv_parser.add_subparsers(
        dest="advisory_action",
        title="actions",
    )

    lookup_parser = adv_subparsers.add_parser("lookup", help="Search for advisories in the local database.")
    lookup_group = lookup_parser.add_mutually_exclusive_group(required=True)
    lookup_group.add_argument("-p", "--package", help="Package name to lookup.")
    lookup_group.add_argument("-i", "--id", help="Advisory ID (e.g. GHSA-xxx, PYSEC-xxx, CVE-xxx).")

    sync_parser = adv_subparsers.add_parser("sync", help="Sync advisories from OSV for a package.")
    sync_parser.add_argument("-p", "--package", required=True, help="Package name to synchronize.")

    adv_parser.set_defaults(handler=_cmd_advisory)

    # 3. 'db' subcommand
    db_parser = subparsers.add_parser(
        "db",
        help="Manage the local TracerPyX SQLite database.",
        formatter_class=argparse.ArgumentDefaultsHelpFormatter,
    )
    db_parser.add_argument(
        "--db-path",
        default="~/.tracerpyx/tracerpyx.db",
        help="Path to SQLite database file.",
    )
    db_subparsers = db_parser.add_subparsers(
        dest="db_action",
        title="actions",
    )
    db_subparsers.add_parser("status", help="Show database migration status and statistics.")
    db_subparsers.add_parser("migrate", help="Run pending schema migrations.")
    db_subparsers.add_parser("clear-cache", help="Purge cached diffs, queries, and AST facts.")
    db_parser.set_defaults(handler=_cmd_db)

    return parser


def main(argv: Sequence[str] | None = None) -> int:
    """Primary CLI entrypoint function."""
    parser = build_parser()
    args = parser.parse_args(argv)

    # Configure logging based on user flags
    log_level = "INFO"
    if args.verbose:
        log_level = "DEBUG"
    elif args.quiet:
        log_level = "WARNING"

    configure_logging(level=log_level, log_file=args.log_file)

    if not args.command:
        parser.print_help()
        return 0

    handler = getattr(args, "handler", None)
    if handler:
        try:
            return handler(args)
        except Exception as exc:
            logger.exception("Command execution failed: %s", exc)
            return 1

    parser.print_help()
    return 0


if __name__ == "__main__":
    sys.exit(main())
