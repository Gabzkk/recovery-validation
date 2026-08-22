from __future__ import annotations

import argparse
import json
import sys
from collections.abc import Sequence
from pathlib import Path

from recovery_validation.config import load_config
from recovery_validation.engine import run_exercise
from recovery_validation.errors import RecoveryValidationError


def build_parser() -> argparse.ArgumentParser:
    parser = argparse.ArgumentParser(
        prog="recovery-validation",
        description="Run a contained AES-256-GCM backup recovery exercise.",
    )
    subparsers = parser.add_subparsers(dest="command", required=True)
    run_parser = subparsers.add_parser("run", help="execute one recovery validation")
    run_parser.add_argument("--config", type=Path, required=True, help="path to TOML configuration")
    return parser


def main(argv: Sequence[str] | None = None) -> int:
    parser = build_parser()
    arguments = parser.parse_args(argv)
    try:
        config = load_config(arguments.config)
        report = run_exercise(config)
    except RecoveryValidationError as error:
        print(
            json.dumps(
                {
                    "status": "ERROR",
                    "error_type": type(error).__name__,
                    "message": str(error),
                },
                sort_keys=True,
            ),
            file=sys.stderr,
        )
        return 2
    print(
        json.dumps(
            {
                "status": report.status,
                "correlation_id": report.correlation_id,
                "files_discovered": report.files_discovered,
                "files_verified": report.files_verified,
                "rto_status": report.rto.status,
                "rpo_status": report.rpo.status,
            },
            sort_keys=True,
        )
    )
    return 0 if report.status == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
