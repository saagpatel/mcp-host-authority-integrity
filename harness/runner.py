"""Command-line entry point for the gated MHAI program."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.program import run_complete_program
from harness.qualification import qualify
from harness.schema_validation import load_json, validate_case_contract

ROOT = Path(__file__).resolve().parents[1]


def list_cases() -> int:
    cases = load_json(ROOT / "cases.json")
    schema = load_json(ROOT / "schemas" / "test-case.schema.json")
    for case in cases:
        validate_case_contract(case, schema)
        browser = " browser" if case["requires_browser"] else ""
        print(f"{case['case_id']}\t{case['execution_family']}\t{case['coverage_level']}{browser}")
    print(f"total\t{len(cases)}")
    return 0


def run_qualification() -> int:
    receipt, path = qualify()
    summary = {
        "result": receipt["result"],
        "run_id": receipt["run_id"],
        "browser_mode": receipt["browser_mode"],
        "checks": {
            item["check_id"]: item["result"]
            for item in receipt["checks"]
        },
        "receipt": str(path),
    }
    print(json.dumps(summary, sort_keys=True))
    return 0 if receipt["result"] == "PASS" else 2


def run_safe() -> int:
    try:
        manifest, path = run_complete_program()
    except RuntimeError as exc:
        print(json.dumps({"result": "REFUSED", "reason": str(exc)}, sort_keys=True))
        return 3
    print(
        json.dumps(
            {
                "result": "COMPLETE",
                "run_id": manifest["run_id"],
                "case_count": manifest["case_count"],
                "result_counts": manifest["result_counts"],
                "containment": "exact immutable qualification binding remained current",
                "manifest": str(path),
            },
            sort_keys=True,
        )
    )
    return 0


def main() -> int:
    parser = argparse.ArgumentParser(prog="mhai")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    commands.add_parser("qualify")
    commands.add_parser("run-safe")
    args = parser.parse_args()
    if args.command == "list":
        return list_cases()
    if args.command == "qualify":
        return run_qualification()
    return run_safe()


if __name__ == "__main__":
    raise SystemExit(main())
