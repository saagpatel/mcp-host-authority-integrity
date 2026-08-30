#!/usr/bin/env python3
"""Run the deterministic MCP Task Lease Guard against synthetic fixtures."""

from __future__ import annotations

import argparse
import json
import sys
from pathlib import Path

ROOT = Path(__file__).resolve().parents[1]
if str(ROOT) not in sys.path:
    sys.path.insert(0, str(ROOT))

from task_lease_guard.checker import (  # noqa: E402
    CATALOG_PATH,
    evaluate_catalog,
    load_catalog,
)


def main() -> int:
    parser = argparse.ArgumentParser(prog="check-task-lease-guard")
    parser.add_argument("--cases", type=Path, default=CATALOG_PATH)
    parser.add_argument("--output", type=Path)
    args = parser.parse_args()
    report = evaluate_catalog(load_catalog(args.cases))
    rendered = json.dumps(report, indent=2, sort_keys=True) + "\n"
    if args.output is None:
        print(rendered, end="")
    else:
        args.output.write_text(rendered, encoding="utf-8")
    return 0 if report["suite_result"] == "PASS" else 1


if __name__ == "__main__":
    raise SystemExit(main())
