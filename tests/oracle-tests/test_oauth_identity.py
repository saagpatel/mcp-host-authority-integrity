from __future__ import annotations

import tempfile
import unittest
from pathlib import Path

from harness.execution import RunContext, deterministic_declared_result
from harness.qualification import ROOT
from harness.schema_validation import load_json
from suite_impl.oauth_identity import evaluate


class OAuthIdentityOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = {
            case["case_id"]: case
            for case in load_json(ROOT / "cases.json")
            if case["case_id"].startswith("OA-")
        }

    def test_non_browser_oauth_cases_exercise_both_controls(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            root = Path(temporary)
            context = RunContext(
                "oauth-oracle-test",
                root,
                "BROWSER_DISABLED",
                "0" * 64,
            )
            for case_id in ("OA-001", "OA-002", "OA-003"):
                with self.subTest(case_id=case_id):
                    case_context = context.for_case(case_id)
                    case_context.case_root.mkdir()
                    evaluation = evaluate(self.cases[case_id], case_context)
                    self.assertEqual(deterministic_declared_result(evaluation), "PASS")
                    self.assertEqual(evaluation.positive_control, "PASS")
                    self.assertEqual(evaluation.negative_control, "PASS")

    def test_browser_oauth_cases_are_hard_blocked(self) -> None:
        context = RunContext(
            "oauth-browser-refusal",
            ROOT / "work/unused-oauth-browser-refusal",
            "BROWSER_DISABLED",
            "0" * 64,
        )
        for case_id in ("OA-004", "OA-005", "OA-006"):
            with self.subTest(case_id=case_id):
                evaluation = evaluate(self.cases[case_id], context.for_case(case_id))
                self.assertEqual(
                    deterministic_declared_result(evaluation),
                    "BLOCKED_BY_ACCESS",
                )
                self.assertEqual(evaluation.positive_control, "NOT_RUN")
                self.assertEqual(evaluation.negative_control, "NOT_RUN")


if __name__ == "__main__":
    unittest.main()
