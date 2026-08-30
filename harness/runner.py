"""Command-line entry point for the gated MHAI program."""

from __future__ import annotations

import argparse
import json
from pathlib import Path

from harness.closure_epoch import close_epoch, open_epoch
from harness.program import run_complete_program
from harness.qualification import qualify
from harness.schema_validation import load_json, validate_case_contract
from task_lease_guard.checker import evaluate_catalog as evaluate_task_lease_catalog
from task_lease_guard.checker import load_catalog as load_task_lease_catalog

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


def run_task_lease_check() -> int:
    """Evaluate only the bundled synthetic Task Lease Guard fixtures."""
    report = evaluate_task_lease_catalog(load_task_lease_catalog())
    print(json.dumps(report, indent=2, sort_keys=True))
    return 0 if report["suite_result"] == "PASS" else 1


def run_epoch_open() -> int:
    receipt, path = open_epoch()
    print(
        json.dumps(
            {
                "result": "OPEN",
                "epoch_id": receipt["epoch_id"],
                "program_commit": receipt["program_commit"],
                "receipt": str(path),
            },
            sort_keys=True,
        )
    )
    return 0


def run_epoch_close() -> int:
    receipt, path = close_epoch()
    print(
        json.dumps(
            {
                "result": receipt["result"],
                "epoch_id": receipt["epoch_id"],
                "run_id": receipt["run_id"],
                "no_forbidden_mutation_gate": receipt[
                    "no_forbidden_mutation_gate"
                ],
                "remaining_blockers": len(receipt["remaining_blockers"]),
                "receipt": str(path),
            },
            sort_keys=True,
        )
    )
    return 0 if receipt["result"] == "PASS_WITH_HISTORICAL_EXCEPTION" else 4


def main() -> int:
    parser = argparse.ArgumentParser(prog="mhai")
    commands = parser.add_subparsers(dest="command", required=True)
    commands.add_parser("list")
    commands.add_parser("qualify")
    commands.add_parser("run-safe")
    commands.add_parser("task-lease-check")
    commands.add_parser("epoch-open")
    commands.add_parser("epoch-close")
    args = parser.parse_args()
    if args.command == "list":
        return list_cases()
    if args.command == "qualify":
        return run_qualification()
    if args.command == "run-safe":
        return run_safe()
    if args.command == "task-lease-check":
        return run_task_lease_check()
    if args.command == "epoch-open":
        return run_epoch_open()
    return run_epoch_close()


if __name__ == "__main__":
    raise SystemExit(main())
