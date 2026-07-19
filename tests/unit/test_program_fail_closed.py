from __future__ import annotations

import json
import shutil
import tempfile
import unittest
from pathlib import Path
from unittest.mock import patch

from harness.execution import Evaluation, RunContext
from harness.program import ProgramExecutionError, run_complete_program
from harness.qualification import ROOT
from harness.schema_validation import canonical_digest, load_json


class ProgramFailClosedTests(unittest.TestCase):
    def test_cleanup_failure_aborts_and_marks_every_later_case_not_run(self) -> None:
        qualification = load_json(
            ROOT / "results/latest/containment-qualification.json"
        )
        with tempfile.TemporaryDirectory() as temporary:
            fake_root = Path(temporary) / "program"
            (fake_root / "schemas").mkdir(parents=True)
            shutil.copy2(ROOT / "cases.json", fake_root / "cases.json")
            shutil.copy2(
                ROOT / "schemas/result.schema.json",
                fake_root / "schemas/result.schema.json",
            )
            shutil.copy2(
                ROOT / "schemas/run-manifest.schema.json",
                fake_root / "schemas/run-manifest.schema.json",
            )
            run_root = fake_root / "work/temporary-state/fail-closed-run"
            run_root.mkdir(parents=True)
            context = RunContext(
                run_id="fail-closed-run",
                run_root=run_root,
                browser_mode="BROWSER_DISABLED",
                qualification_digest=canonical_digest(qualification),
                qualification_run_id=qualification["run_id"],
                qualification_receipt_json=json.dumps(
                    qualification,
                    sort_keys=True,
                    separators=(",", ":"),
                ),
                fixture_digest="0" * 64,
            )
            evaluator_calls: list[str] = []

            def evaluator(case: dict, _context: RunContext) -> Evaluation:
                evaluator_calls.append(case["case_id"])
                return Evaluation(
                    target_verdict="PASS",
                    observations=[{"synthetic": True}],
                )

            real_rmtree = shutil.rmtree
            cleanup_calls = 0

            def fail_first_case_cleanup(path: Path, *args: object, **kwargs: object) -> None:
                nonlocal cleanup_calls
                cleanup_calls += 1
                if cleanup_calls == 1:
                    raise OSError("synthetic cleanup failure")
                real_rmtree(path, *args, **kwargs)

            with (
                patch("harness.program.ROOT", fake_root),
                patch("harness.program.new_context", return_value=context),
                patch("harness.program.evaluator_for", return_value=evaluator),
                patch(
                    "harness.program.shutil.rmtree",
                    side_effect=fail_first_case_cleanup,
                ),self.assertRaises(ProgramExecutionError)
            ):
                run_complete_program()

            manifests = list(
                (fake_root / "results/runs/fail-closed-run").glob("run-manifest.json")
            )
            self.assertEqual(len(manifests), 1)
            manifest = load_json(manifests[0])
            self.assertFalse(manifest["complete"])
            self.assertEqual(manifest["cleanup_result"], "FAIL")
            self.assertEqual(
                manifest["result_counts"],
                {"ERROR": 1, "NOT_RUN": 56},
            )
            self.assertEqual(evaluator_calls, ["RT-001"])
            self.assertFalse(
                (fake_root / "results/latest/run-manifest.json").exists()
            )

    def test_context_rejects_a_different_qualification_snapshot(self) -> None:
        qualification = load_json(
            ROOT / "results/latest/containment-qualification.json"
        )
        context = RunContext(
            run_id="binding-test",
            run_root=ROOT / "work/unused-binding-test",
            browser_mode="BROWSER_DISABLED",
            qualification_digest="0" * 64,
            qualification_run_id=qualification["run_id"],
            qualification_receipt_json=json.dumps(qualification),
        )
        with self.assertRaisesRegex(RuntimeError, "no longer matches"):
            context.bound_qualification()


if __name__ == "__main__":
    unittest.main()
