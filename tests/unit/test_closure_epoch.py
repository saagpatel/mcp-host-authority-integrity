from __future__ import annotations

import subprocess
import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.closure_epoch import (
    ROOT,
    TargetPolicy,
    _archive_and_verify,
    _metadata_digest,
    _target_access_checks,
    safe_git,
    target_observation,
)
from tests.helpers import synthetic_closure_epoch


class ClosureEpochTests(unittest.TestCase):
    def test_safe_git_enforces_both_optional_lock_controls(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout=b"head\n", stderr=b"")
        with (
            tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary,
            patch(
                "harness.closure_epoch.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            output = safe_git(
                Path(temporary),
                ["rev-parse", "HEAD"],
                home=Path(temporary) / "home",
            )
        self.assertEqual(output, b"head\n")
        arguments = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertEqual(arguments[:2], ["git", "--no-optional-locks"])
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")

    def test_metadata_digest_detects_a_stat_change(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            root = Path(temporary)
            path = root / "value"
            path.write_text("one", encoding="utf-8")
            before = _metadata_digest(root)
            path.write_text("two-two", encoding="utf-8")
            after = _metadata_digest(root)
        self.assertNotEqual(before, after)

    def test_git_archive_is_verified_against_every_tree_blob(self) -> None:
        with tempfile.TemporaryDirectory(dir=ROOT / "work") as temporary:
            root = Path(temporary)
            source = root / "source"
            source.mkdir()
            subprocess.run(["git", "init", "-q", str(source)], check=True)
            subprocess.run(
                ["git", "-C", str(source), "config", "user.email", "unit@example.invalid"],
                check=True,
            )
            subprocess.run(
                ["git", "-C", str(source), "config", "user.name", "Unit"],
                check=True,
            )
            (source / "payload.txt").write_text("exact\n", encoding="utf-8")
            subprocess.run(["git", "-C", str(source), "add", "payload.txt"], check=True)
            subprocess.run(["git", "-C", str(source), "commit", "-qm", "fixture"], check=True)
            home = root / "home"
            head = safe_git(source, ["rev-parse", "HEAD"], home=home).decode().strip()
            receipt = _archive_and_verify(
                TargetPolicy(
                    "unit-source",
                    source,
                    ("UNIT-001",),
                    "CLEAR",
                    "unit",
                    archive_allowed=True,
                ),
                head=head,
                epoch_root=root / "epoch",
                home=home,
            )
        self.assertTrue(receipt["fidelity_proven"])
        self.assertEqual(receipt["file_count"], 1)
        self.assertEqual(receipt["immutable_mode"], "0444")

    def test_frozen_target_identity_is_unique_per_case(self) -> None:
        receipt = synthetic_closure_epoch()
        self.assertEqual(target_observation(receipt, "RT-012")["head"], "1" * 40)
        self.assertEqual(target_observation(receipt, "HC-012")["head"], "2" * 40)

    def test_closeout_uses_case_evidence_without_final_target_inventory(self) -> None:
        results = [
            {
                "case_id": "RT-012",
                "result": "BLOCKED_BY_ACCESS",
                "observations": [{"target_code_executed": False}],
            },
            {
                "case_id": "HC-011",
                "result": "BLOCKED_BY_ACCESS",
                "observations": [
                    {
                        "unsafe_fallback_refused": True,
                        "target_code_executed": False,
                    }
                ],
            },
            {
                "case_id": "HC-012",
                "result": "BLOCKED_BY_ACCESS",
                "observations": [
                    {
                        "target_repository_accessed_during_case": False,
                        "target_code_executed": False,
                    }
                ],
            },
            {
                "case_id": "LP-007",
                "result": "BLOCKED_BY_ACCESS",
                "observations": [
                    {
                        "target_access": "frozen closure-epoch identity only",
                        "target_code_executed": False,
                    }
                ],
            },
            {
                "case_id": "LP-009",
                "result": "BLOCKED_BY_ACCESS",
                "observations": [
                    {
                        "target_access": "frozen closure-epoch identity only",
                        "target_code_executed": False,
                    }
                ],
            },
        ]
        checks = _target_access_checks(synthetic_closure_epoch(), results)
        self.assertEqual(len(checks), 4)
        self.assertTrue(all(item["case_evidence_valid"] for item in checks))
        self.assertTrue(all(item["post_open_access"] == "NONE" for item in checks))
        self.assertTrue(
            all(
                item["final_observation"]
                == "none; no final target inventory or Git command"
                for item in checks
            )
        )


if __name__ == "__main__":
    unittest.main()
