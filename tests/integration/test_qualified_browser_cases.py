from __future__ import annotations

import shutil
import tempfile
import unittest
from pathlib import Path

from harness.execution import (
    RunContext,
    build_result,
    deterministic_declared_result,
    fixture_digest,
    utc_now,
)
from harness.program import evaluator_for
from harness.qualification import ROOT
from harness.schema_validation import load_json
from tests.helpers import closure_context_fields


class QualifiedBrowserCaseTests(unittest.TestCase):
    def test_all_safely_obtainable_browser_cases_execute_both_controls(self) -> None:
        browser_case_ids = (
            "HC-001",
            "HC-005",
            "HC-006",
            "HC-009",
            "OA-004",
            "OA-005",
            "OA-006",
        )
        cases = {
            case["case_id"]: case
            for case in load_json(ROOT / "cases.json")
            if case["case_id"] in browser_case_ids
        }
        self.assertEqual(set(cases), set(browser_case_ids))
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            run_root = Path(temporary)
            context = RunContext(
                run_id="qualified-browser-integration",
                run_root=run_root,
                browser_mode="QUALIFIED",
                qualification_digest="0" * 64,
                fixture_digest=fixture_digest(),
                **closure_context_fields(),
            )
            for case_id in browser_case_ids:
                with self.subTest(case_id=case_id):
                    case = cases[case_id]
                    case_context = context.for_case(case_id)
                    case_context.case_root.mkdir(mode=0o700)
                    evaluation = evaluator_for(case)(case, case_context)
                    self.assertEqual(deterministic_declared_result(evaluation), "PASS")
                    self.assertEqual(evaluation.positive_control, "PASS")
                    self.assertEqual(evaluation.negative_control, "PASS")
                    self.assertEqual(evaluation.containment_result, "PASS")
                    self.assertEqual(evaluation.cleanup_result, "PASS")
                    result = build_result(case, case_context, evaluation, utc_now())
                    self.assertEqual(result["result"], "PASS")
                    browser_observation = next(
                        item
                        for item in evaluation.observations
                        if item.get("kind") == "browser-fixture-controls"
                    )
                    self.assertTrue(browser_observation["separate_fresh_profiles"])
                    self.assertTrue(browser_observation["profile_cleanup_verified"])
                    shutil.rmtree(case_context.case_root)


if __name__ == "__main__":
    unittest.main()
