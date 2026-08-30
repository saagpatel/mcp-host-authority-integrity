from __future__ import annotations

import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path
from typing import Any

from harness.schema_validation import load_json, validate
from task_lease_guard.checker import evaluate_case, evaluate_catalog, load_catalog

ROOT = Path(__file__).resolve().parents[2]


class TaskLeaseGuardTests(unittest.TestCase):
    catalog: dict[str, Any]
    cases: dict[str, dict[str, Any]]

    @classmethod
    def setUpClass(cls) -> None:
        cls.catalog = load_catalog()
        cls.cases = {case["case_id"]: case for case in cls.catalog["cases"]}

    def test_catalog_and_report_validate(self) -> None:
        report = evaluate_catalog(self.catalog)
        validate(report, load_json(ROOT / "schemas" / "task-lease-guard-report.schema.json"))
        self.assertEqual(report["suite_result"], "PASS")
        self.assertEqual(report["expectation_mismatches"], [])
        self.assertEqual(sum(report["outcome_counts"].values()), report["case_count"])

    def test_exact_case_inventory_and_outcomes(self) -> None:
        self.assertEqual(sorted(self.cases), [f"TLG-{index:03d}" for index in range(1, 31)])
        outcomes = Counter(case["expected_outcome"] for case in self.cases.values())
        self.assertEqual(outcomes, {"FAIL": 17, "PASS": 9, "UNKNOWN": 4})

    def test_every_requested_adversarial_family_is_explicit(self) -> None:
        required = {
            "guessed or low-entropy task IDs": "TLG-003",
            "cross-requestor result retrieval": "TLG-004",
            "context changes during polling": "TLG-005",
            "expired-task replay": "TLG-006",
            "result access after cancellation": "TLG-007",
            "undeclared task capability use": "TLG-002",
            "task ID reuse": "TLG-008",
            "forged terminal state": "TLG-009",
            "polling before creation": "TLG-010",
            "sensitive elicitation nested inside a task": "TLG-011",
        }
        for family, case_id in required.items():
            with self.subTest(family=family):
                self.assertIn(case_id, self.cases)
                self.assertIn(evaluate_case(self.cases[case_id])["outcome"], {"FAIL", "UNKNOWN"})

    def test_version_profiles_do_not_share_wire_semantics(self) -> None:
        self.assertEqual(evaluate_case(self.cases["TLG-001"])["outcome"], "PASS")
        self.assertEqual(
            evaluate_case(self.cases["TLG-022"])["reason_codes"],
            ["unsupported_result_retrieval"],
        )
        self.assertEqual(
            evaluate_case(self.cases["TLG-020"])["reason_codes"],
            ["failure_status_mismatch"],
        )

    def test_current_extension_requires_server_generated_task_ids(self) -> None:
        case = json.loads(json.dumps(self.cases["TLG-028"]))
        case["fixture"]["events"][1]["id_issuer"] = "receiver"
        result = evaluate_case(case)
        self.assertEqual(result["outcome"], "FAIL")
        self.assertEqual(result["reason_codes"], ["invalid_task_id_issuer"])

    def test_unknowns_preserve_specification_gaps(self) -> None:
        expected = {
            "TLG-006": "expired_task_retention_unspecified",
            "TLG-025": "cancelled_result_custody_unspecified",
            "TLG-026": "requestor_binding_unavailable",
            "TLG-027": "quantitative_entropy_threshold_unspecified",
        }
        for case_id, reason in expected.items():
            with self.subTest(case_id=case_id):
                result = evaluate_case(self.cases[case_id])
                self.assertEqual(result["outcome"], "UNKNOWN")
                self.assertIn(reason, result["reason_codes"])

    def test_capability_context_cancellation_and_custody_fail_closed(self) -> None:
        expected = {
            "TLG-002": "undeclared_task_capability",
            "TLG-004": "authorization_context_mismatch",
            "TLG-007": "authorization_context_mismatch",
            "TLG-018": "terminal_result_mismatch",
        }
        for case_id, reason in expected.items():
            with self.subTest(case_id=case_id):
                result = evaluate_case(self.cases[case_id])
                self.assertEqual(result["outcome"], "FAIL")
                self.assertEqual(result["reason_codes"], [reason])

    def test_elicitation_and_sampling_keep_standalone_trust(self) -> None:
        self.assertEqual(
            evaluate_case(self.cases["TLG-011"])["reason_codes"],
            ["sensitive_form_elicitation"],
        )
        self.assertEqual(evaluate_case(self.cases["TLG-012"])["outcome"], "PASS")
        self.assertEqual(
            evaluate_case(self.cases["TLG-013"])["reason_codes"],
            ["undeclared_nested_capability"],
        )
        self.assertEqual(evaluate_case(self.cases["TLG-014"])["outcome"], "PASS")
        self.assertEqual(evaluate_case(self.cases["TLG-029"])["outcome"], "PASS")

    def test_polling_uses_the_latest_suggested_interval(self) -> None:
        result = evaluate_case(self.cases["TLG-030"])
        self.assertEqual(result["outcome"], "PASS")
        self.assertEqual(
            [check["code"] for check in result["checks"]].count("poll_accepted"),
            2,
        )

    def test_evaluation_is_deterministic(self) -> None:
        first = evaluate_catalog(self.catalog)
        second = evaluate_catalog(json.loads(json.dumps(self.catalog)))
        self.assertEqual(first, second)

    def test_cli_emits_machine_readable_report(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/check_task_lease_guard.py"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stderr)
        report = json.loads(completed.stdout)
        self.assertEqual(report["schema_version"], "TaskLeaseGuardReportV1")
        self.assertEqual(report["proof_boundary"], "LOCAL_SYNTHETIC_FIXTURE")

    def test_protocol_drift_binds_to_existing_corpus(self) -> None:
        drift = load_json(ROOT / "task_lease_guard" / "protocol-drift.json")
        registry = load_json(ROOT / "sources" / "source-registry.json")
        source_ids = {source["source_id"] for source in registry["sources"]}
        self.assertIn(drift["baseline_corpus"]["source_id"], source_ids)
        main_cases = {case["case_id"] for case in load_json(ROOT / "cases.json")}
        self.assertLessEqual(set(drift["baseline_corpus"]["case_ids"]), main_cases)
        self.assertEqual(drift["classification"], "MATERIAL_BREAKING_PROTOCOL_DRIFT")
        self.assertEqual(
            [change["drift_id"] for change in drift["changes"]],
            [f"TPD-{index:03d}" for index in range(1, 8)],
        )
        self.assertTrue(
            all(item["status"] == "UNKNOWN" for item in drift["unresolved_specification_questions"])
        )
        self.assertEqual(
            [item["question_id"] for item in drift["unresolved_specification_questions"]],
            ["TPU-002", "TPU-003", "TPU-004"],
        )
        self.assertEqual(
            drift["resolved_specification_questions"],
            [
                {
                    "question_id": "TPU-001",
                    "topic": "missing-capability-error-code",
                    "status": "RESOLVED",
                    "detail": (
                        "The current hosted Tasks draft and current core schema consistently use "
                        "-32021 (Missing Required Client Capability)."
                    ),
                    "source_commit": "7b8e2bde214b35fd6f0d4f3899789388d623164d",
                    "verified_at": "2026-08-30",
                }
            ],
        )


if __name__ == "__main__":
    unittest.main()
