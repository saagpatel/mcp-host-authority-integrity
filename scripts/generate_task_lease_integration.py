#!/usr/bin/env python3
"""Generate or verify the additive 87-case Task Lease Guard baseline."""

from __future__ import annotations

import argparse
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from task_lease_guard.integration import (  # noqa: E402
    BASELINE_PATH,
    IntegrationBaselineError,
    render_integration_baseline,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="generate-task-lease-integration")
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    try:
        expected = render_integration_baseline()
    except IntegrationBaselineError as exc:
        print(f"integration baseline refused: {exc}", file=sys.stderr)
        return 2
    if args.write:
        BASELINE_PATH.write_text(expected, encoding="utf-8")
        print("wrote additive 87-case integration baseline")
        return 0
    if not BASELINE_PATH.exists() or BASELINE_PATH.read_text(encoding="utf-8") != expected:
        print("generated output differs: task_lease_guard/integration-baseline.json")
        return 1
    print("verified additive 87-case integration baseline")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
