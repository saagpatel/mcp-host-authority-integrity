from __future__ import annotations

import hashlib
import json
import subprocess
import sys
import unittest
from pathlib import Path

from harness.schema_validation import canonical_digest, load_json, validate
from task_lease_guard.integration import (
    CURRENT_SOURCE_IDS,
    HISTORICAL_CATALOG_SHA256,
    HISTORICAL_RESULTS_TREE_SHA256,
    HISTORICAL_SA_DEFINITIONS_SHA256,
    PRIOR_SOURCE_COUNT,
    PRIOR_SOURCES_SHA256,
    build_integration_baseline,
)

ROOT = Path(__file__).resolve().parents[2]


class TaskLeaseIntegrationTests(unittest.TestCase):
    def test_generated_baseline_is_exact_and_schema_valid(self) -> None:
        baseline = load_json(ROOT / "task_lease_guard" / "integration-baseline.json")
        validate(
            baseline,
            load_json(ROOT / "schemas" / "integrated-catalog-baseline.schema.json"),
        )
        self.assertEqual(baseline, build_integration_baseline())
        self.assertEqual(baseline["combined_catalog"]["case_count"], 87)
        self.assertEqual(len(set(baseline["combined_catalog"]["ordered_case_ids"])), 87)

    def test_historical_catalog_and_sa_meanings_are_immutable(self) -> None:
        historical_path = ROOT / "cases.json"
        self.assertEqual(
            hashlib.sha256(historical_path.read_bytes()).hexdigest(),
            HISTORICAL_CATALOG_SHA256,
        )
        cases = load_json(historical_path)
        self.assertEqual(len(cases), 57)
        sa_cases = [case for case in cases if case["case_id"].startswith("SA-")]
        self.assertEqual(len(sa_cases), 15)
        self.assertEqual(canonical_digest(sa_cases), HISTORICAL_SA_DEFINITIONS_SHA256)

    def test_registry_appends_only_the_approved_current_sources(self) -> None:
        registry = load_json(ROOT / "sources" / "source-registry.json")
        self.assertEqual(canonical_digest(registry["sources"][:PRIOR_SOURCE_COUNT]), PRIOR_SOURCES_SHA256)
        self.assertEqual(
            [source["source_id"] for source in registry["sources"][PRIOR_SOURCE_COUNT:]],
            CURRENT_SOURCE_IDS,
        )
        self.assertEqual(registry["sources_digest"], canonical_digest(registry["sources"]))

    def test_historical_receipts_are_bound_without_rewriting(self) -> None:
        baseline = build_integration_baseline()
        self.assertTrue(baseline["historical_receipts"]["immutable"])
        self.assertEqual(
            baseline["historical_receipts"]["tree_sha256"],
            HISTORICAL_RESULTS_TREE_SHA256,
        )
        self.assertEqual(baseline["historical_receipts"]["file_count"], 2057)
        self.assertEqual(baseline["historical_receipts"]["ledger_claim_file_count"], 1567)

    def test_fixture_only_mhai_command_emits_tlg_report_without_receipts(self) -> None:
        before = build_integration_baseline()["historical_receipts"]
        completed = subprocess.run(
            [sys.executable, "-m", "harness.runner", "task-lease-check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schema_version"], "TaskLeaseGuardReportV1")
        self.assertEqual(report["case_count"], 30)
        self.assertEqual(report["proof_boundary"], "LOCAL_SYNTHETIC_FIXTURE")
        self.assertEqual(build_integration_baseline()["historical_receipts"], before)

    def test_integration_generator_is_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/generate_task_lease_integration.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)


if __name__ == "__main__":
    unittest.main()
