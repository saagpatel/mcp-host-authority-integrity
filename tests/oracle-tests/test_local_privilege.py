from __future__ import annotations

import json
import tempfile
import unittest
from pathlib import Path

from harness.execution import (
    RunContext,
    deterministic_declared_result,
    fixture_digest,
)
from harness.qualification import ROOT
from harness.schema_validation import canonical_digest, load_json
from suite_impl.local_privilege import evaluate


class LocalPrivilegeOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {
            case["case_id"]: case
            for case in load_json(ROOT / "cases.json")
            if case["case_id"].startswith("LP-")
        }
        cls.qualification = load_json(
            ROOT / "results/latest/containment-qualification.json"
        )

    def test_exact_local_privilege_case_set(self) -> None:
        self.assertEqual(
            sorted(self.cases),
            [f"LP-{index:03d}" for index in range(1, 12)],
        )

    def test_fixture_and_static_cases_pass_exact_oracles(self) -> None:
        expected_pass = {
            "LP-001",
            "LP-002",
            "LP-003",
            "LP-004",
            "LP-005",
            "LP-006",
            "LP-008",
            "LP-010",
            "LP-011",
        }
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            context = RunContext(
                "local-privilege-oracle",
                Path(temporary),
                "BROWSER_DISABLED",
                canonical_digest(self.qualification),
                qualification_run_id=self.qualification["run_id"],
                qualification_receipt_json=json.dumps(
                    self.qualification,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                fixture_digest=fixture_digest(),
            )
            for case_id in sorted(expected_pass):
                with self.subTest(case_id=case_id):
                    case_context = context.for_case(case_id)
                    case_context.case_root.mkdir(parents=True)
                    evaluation = evaluate(self.cases[case_id], case_context)
                    self.assertEqual(deterministic_declared_result(evaluation), "PASS")
                    self.assertEqual(evaluation.positive_control, "PASS")
                    self.assertEqual(evaluation.negative_control, "PASS")

    def test_unapproved_isolated_copies_are_blocked(self) -> None:
        context = RunContext(
            "local-copy-refusal",
            ROOT / "work/unused-local-copy-refusal",
            "BROWSER_DISABLED",
            "0" * 64,
        )
        for case_id in ("LP-007", "LP-009"):
            with self.subTest(case_id=case_id):
                evaluation = evaluate(self.cases[case_id], context.for_case(case_id))
                self.assertEqual(
                    deterministic_declared_result(evaluation),
                    "BLOCKED_BY_ACCESS",
                )
                self.assertFalse(evaluation.observations[0]["isolated_copy_created"])
                self.assertTrue(evaluation.observations[0]["overclaim_refused"])


if __name__ == "__main__":
    unittest.main()
