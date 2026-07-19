from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from collections import Counter
from pathlib import Path

from harness.execution import RunContext, build_result, fixture_digest, utc_now
from harness.program import evaluator_for
from harness.qualification import ROOT
from harness.schema_validation import canonical_digest, load_json
from tests.helpers import closure_context_fields


class AllCaseContractTests(unittest.TestCase):
    def test_every_case_evaluator_builds_one_schema_valid_result(self) -> None:
        cases = load_json(ROOT / "cases.json")
        results: list[dict] = []
        qualification = load_json(
            ROOT / "results/latest/containment-qualification.json"
        )
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            context = RunContext(
                run_id="all-case-contract-test",
                run_root=Path(temporary),
                browser_mode="BROWSER_DISABLED",
                qualification_digest=canonical_digest(qualification),
                qualification_run_id=qualification["run_id"],
                qualification_receipt_json=json.dumps(
                    qualification,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                fixture_digest=fixture_digest(),
                **closure_context_fields(),
            )
            for case in cases:
                with self.subTest(case_id=case["case_id"]):
                    case_context = context.for_case(case["case_id"])
                    case_context.case_root.mkdir(parents=True, mode=0o700)
                    evaluation = evaluator_for(case)(case, case_context)
                    result = build_result(case, case_context, evaluation, utc_now())
                    self.assertEqual(result["case_id"], case["case_id"])
                    results.append(result)
                    shutil.rmtree(case_context.case_root)
        self.assertEqual(len(results), 57)
        self.assertEqual(len({item["case_id"] for item in results}), 57)
        self.assertEqual(
            Counter(item["result"] for item in results),
            Counter({"PASS": 43, "BLOCKED_BY_ACCESS": 13, "FAIL": 1}),
        )
        blocked_browser = {
            item["case_id"]
            for item in results
            if item["result"] == "BLOCKED_BY_ACCESS"
            and item["case_id"]
            in {
                "HC-001",
                "HC-005",
                "HC-006",
                "HC-009",
                "HC-011",
                "OA-004",
                "OA-005",
                "OA-006",
            }
        }
        self.assertEqual(len(blocked_browser), 8)


if __name__ == "__main__":
    unittest.main()
