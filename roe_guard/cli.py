"""
roe_guard.cli

Command-line interface for roe-guard.

Planned subcommands (T7):
    validate      Validate a policy YAML file.
    check         Evaluate a single (target, action) against a policy.
    audit-verify  Verify the integrity of an audit hash-chain.

This module currently provides a working ``--help`` entry point only;
subcommands will be implemented in T7.
"""

from __future__ import annotations

import argparse
import sys

from roe_guard import __version__


def _build_parser() -> argparse.ArgumentParser:
    """Construct the top-level argument parser."""
    parser = argparse.ArgumentParser(
        prog="roe-guard",
        description=(
            "roe-guard — Rules of Engagement policy enforcement.\n\n"
            "Define what targets, time-windows, and action types are allowed; "
            "every out-of-scope action is denied and logged."
        ),
        formatter_class=argparse.RawDescriptionHelpFormatter,
        epilog=(
            "Subcommands (planned):\n"
            "  validate       Validate a policy YAML file.\n"
            "  check          Evaluate a single target/action against a policy.\n"
            "  audit-verify   Verify the integrity of an audit hash-chain.\n"
            "\n"
            "See: docs/SPEC.md for full documentation."
        ),
    )
    parser.add_argument(
        "-V", "--version",
        action="version",
        version=f"roe-guard {__version__}",
    )
    # Subcommands will be registered here in T7.
    # parser.add_subparsers(dest="command", ...)
    return parser


def main(argv: list[str] | None = None) -> int:
    """CLI entry point.

    Args:
        argv: Optional argument list (defaults to ``sys.argv[1:]``).

    Returns:
        Process exit code (0 on success).
    """
    parser = _build_parser()
    parser.parse_args(argv)
    return 0


if __name__ == "__main__":
    sys.exit(main())
