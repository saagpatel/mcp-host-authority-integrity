from __future__ import annotations

import tempfile
import unittest
from pathlib import Path
from types import SimpleNamespace
from unittest.mock import patch

from harness.regression_drift import (
    DriftCheckError,
    GitReader,
    check_upstream,
    classify_repository,
    decide,
    exit_code,
    validate_baseline_contract,
    validate_report_contract,
)
from harness.schema_validation import load_json


class FakeGitReader:
    def __init__(self, responses: dict[tuple[str, ...], bytes]) -> None:
        self.responses = responses

    def read(
        self,
        repository: Path,
        arguments: list[str],
        timeout: float = 20,
    ) -> bytes:
        del repository, timeout
        return self.responses[tuple(arguments)]


def repository_config(path: Path) -> dict:
    return {
        "path": str(path),
        "baseline_commit": "a" * 40,
        "non_material_paths": ["README*", "docs/**"],
    }


class RegressionDriftTests(unittest.TestCase):
    def test_baseline_nested_contract_fails_closed(self) -> None:
        baseline = load_json(
            Path(__file__).resolve().parents[2] / "regression-baseline.json"
        )
        baseline["targets"][0]["undeclared"] = True
        with self.assertRaises(DriftCheckError):
            validate_baseline_contract(baseline)

    def test_report_nested_contract_fails_closed(self) -> None:
        repository = {
            "name": "program",
            "path": "/program",
            "baseline_commit": "a" * 40,
            "current_commit": "a" * 40,
            "baseline_tree": "b" * 40,
            "current_tree": "b" * 40,
            "working_tree_clean": True,
            "status": "CURRENT",
            "changed_paths": [],
            "material_paths": [],
            "non_material_paths": [],
            "limitations": [],
        }
        report = {
            "schema_version": "MHAI-REGRESSION-DRIFT-1",
            "baseline_id": "unit",
            "checked_at": "2026-07-19T00:00:00Z",
            "git_read_contract": {
                "isolated_disposable_home": True,
                "optional_locks_environment": "0",
                "no_optional_locks_argument": True,
                "target_fetch_performed": False,
            },
            "mutation_boundary": {
                "target_writes": False,
                "target_repairs": False,
                "epoch_opened": False,
                "rerun_authorized": False,
                "durable_report_written": False,
            },
            "program": dict(repository),
            "targets": [dict(repository)],
            "upstream": {"status": "CURRENT", "checks": [], "limitations": []},
            "decision": {
                "status": "NO_RERUN_TRIGGER",
                "reasons": ["unit"],
                "automatic_epoch_authorized": False,
                "next_action": "none",
            },
        }
        report["targets"][0]["undeclared"] = True
        with self.assertRaises(DriftCheckError):
            validate_report_contract(report)

    def test_git_reader_enforces_isolated_no_optional_locks_contract(self) -> None:
        completed = SimpleNamespace(returncode=0, stdout=b"head\n", stderr=b"")
        with (
            tempfile.TemporaryDirectory() as temporary,
            patch(
                "harness.regression_drift.subprocess.run",
                return_value=completed,
            ) as run,
        ):
            reader = GitReader(Path(temporary))
            self.assertEqual(
                reader.read(Path(temporary), ["rev-parse", "HEAD"]),
                b"head\n",
            )
        arguments = run.call_args.args[0]
        environment = run.call_args.kwargs["env"]
        self.assertEqual(arguments[:2], ["git", "--no-optional-locks"])
        self.assertEqual(environment["GIT_OPTIONAL_LOCKS"], "0")
        self.assertEqual(environment["GIT_CONFIG_NOSYSTEM"], "1")

    def test_history_only_change_does_not_trigger(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = "a" * 40
            current = "b" * 40
            tree = "c" * 40
            reader = FakeGitReader(
                {
                    ("cat-file", "-e", f"{baseline}^{{commit}}"): b"",
                    ("rev-parse", "HEAD"): f"{current}\n".encode(),
                    ("rev-parse", "HEAD^{tree}"): f"{tree}\n".encode(),
                    ("rev-parse", f"{baseline}^{{tree}}"): f"{tree}\n".encode(),
                    (
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=all",
                    ): b"",
                    (
                        "diff",
                        "--name-only",
                        "-z",
                        baseline,
                        current,
                        "--",
                    ): b"",
                }
            )
            result = classify_repository(
                repository_config(root),
                reader,
                name="target",
                baseline_tree=tree,
            )
        self.assertEqual(result["status"], "HISTORY_ONLY")

    def test_docs_only_drift_is_non_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = "a" * 40
            current = "b" * 40
            old_tree = "c" * 40
            new_tree = "d" * 40
            reader = FakeGitReader(
                {
                    ("cat-file", "-e", f"{baseline}^{{commit}}"): b"",
                    ("rev-parse", "HEAD"): f"{current}\n".encode(),
                    ("rev-parse", "HEAD^{tree}"): f"{new_tree}\n".encode(),
                    ("rev-parse", f"{baseline}^{{tree}}"): f"{old_tree}\n".encode(),
                    (
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=all",
                    ): b"",
                    (
                        "diff",
                        "--name-only",
                        "-z",
                        baseline,
                        current,
                        "--",
                    ): b"README.md\0docs/contract.md\0",
                }
            )
            result = classify_repository(
                repository_config(root),
                reader,
                name="target",
                baseline_tree=old_tree,
            )
        self.assertEqual(result["status"], "NON_MATERIAL_DRIFT")
        self.assertEqual(result["material_paths"], [])

    def test_runtime_or_dependency_drift_is_material(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = "a" * 40
            current = "b" * 40
            old_tree = "c" * 40
            new_tree = "d" * 40
            reader = FakeGitReader(
                {
                    ("cat-file", "-e", f"{baseline}^{{commit}}"): b"",
                    ("rev-parse", "HEAD"): f"{current}\n".encode(),
                    ("rev-parse", "HEAD^{tree}"): f"{new_tree}\n".encode(),
                    ("rev-parse", f"{baseline}^{{tree}}"): f"{old_tree}\n".encode(),
                    (
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=all",
                    ): b"",
                    (
                        "diff",
                        "--name-only",
                        "-z",
                        baseline,
                        current,
                        "--",
                    ): b"README.md\0src-tauri/Cargo.lock\0",
                }
            )
            result = classify_repository(
                repository_config(root),
                reader,
                name="target",
                baseline_tree=old_tree,
            )
        self.assertEqual(result["status"], "MATERIAL_DRIFT")
        self.assertEqual(result["material_paths"], ["src-tauri/Cargo.lock"])

    def test_dirty_worktree_is_unknown(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            baseline = "a" * 40
            tree = "c" * 40
            reader = FakeGitReader(
                {
                    ("cat-file", "-e", f"{baseline}^{{commit}}"): b"",
                    ("rev-parse", "HEAD"): f"{baseline}\n".encode(),
                    ("rev-parse", "HEAD^{tree}"): f"{tree}\n".encode(),
                    ("rev-parse", f"{baseline}^{{tree}}"): f"{tree}\n".encode(),
                    (
                        "status",
                        "--porcelain=v1",
                        "-z",
                        "--untracked-files=all",
                    ): b"?? scratch.txt\0",
                    (
                        "diff",
                        "--name-only",
                        "-z",
                        baseline,
                        baseline,
                        "--",
                    ): b"",
                }
            )
            result = classify_repository(
                repository_config(root),
                reader,
                name="target",
                baseline_tree=tree,
            )
        self.assertEqual(result["status"], "UNKNOWN")
        self.assertFalse(result["working_tree_clean"])

    def test_upstream_new_stable_release_triggers_change(self) -> None:
        config = {
            "python_sdk": {
                "package": "mcp",
                "registry": "pypi",
                "stable_version": "1.28.1",
            },
            "typescript_sdk": {
                "repository": "modelcontextprotocol/typescript-sdk",
                "stable_tag": "v1.29.0",
            },
            "protocol_issue": {
                "repository": "modelcontextprotocol/modelcontextprotocol",
                "number": 1898,
                "state": "open",
            },
            "conformance_pull_request": {
                "repository": "modelcontextprotocol/conformance",
                "number": 399,
                "state": "open",
                "merged": False,
            },
        }

        def api_read(path: str):
            if path == "https://pypi.org/pypi/mcp/json":
                return {"info": {"version": "1.29.0"}}
            if path.startswith("/repos/modelcontextprotocol/typescript-sdk/releases"):
                return [
                    {
                        "draft": False,
                        "prerelease": False,
                        "tag_name": "v1.29.0",
                        "html_url": "https://example.invalid/typescript",
                    }
                ]
            if path.endswith("/issues/1898"):
                return {"state": "open", "html_url": "https://example.invalid/issue"}
            if path.endswith("/pulls/399"):
                return {
                    "state": "open",
                    "merged_at": None,
                    "html_url": "https://example.invalid/pull",
                }
            raise AssertionError(path)

        result = check_upstream(config, api_read=api_read)
        self.assertEqual(result["status"], "CHANGED")

    def test_latest_stable_selection_ignores_feed_order_and_prereleases(self) -> None:
        config = {
            "python_sdk": {
                "package": "mcp",
                "registry": "pypi",
                "stable_version": "1.28.1",
            },
            "typescript_sdk": {
                "repository": "modelcontextprotocol/typescript-sdk",
                "stable_tag": "v1.29.0",
            },
            "protocol_issue": {
                "repository": "modelcontextprotocol/modelcontextprotocol",
                "number": 1898,
                "state": "open",
            },
            "conformance_pull_request": {
                "repository": "modelcontextprotocol/conformance",
                "number": 399,
                "state": "open",
                "merged": False,
            },
        }

        def api_read(path: str):
            if path == "https://pypi.org/pypi/mcp/json":
                return {"info": {"version": "1.28.1"}}
            if "/releases?" in path:
                return [
                    {
                        "draft": False,
                        "prerelease": True,
                        "tag_name": "v2.0.0-beta.2",
                    },
                    {
                        "draft": False,
                        "prerelease": False,
                        "tag_name": "v1.28.0",
                    },
                    {
                        "draft": False,
                        "prerelease": False,
                        "tag_name": "v1.29.0",
                    },
                ]
            if path.endswith("/issues/1898"):
                return {"state": "open"}
            if path.endswith("/pulls/399"):
                return {"state": "open", "merged_at": None}
            raise AssertionError(path)

        result = check_upstream(config, api_read=api_read)
        self.assertEqual(result["status"], "CURRENT")

    def test_decision_precedence_is_material_then_unknown_then_current(self) -> None:
        current = {"status": "CURRENT"}
        history = {"name": "target", "status": "HISTORY_ONLY"}
        material = {"name": "target", "status": "MATERIAL_DRIFT"}
        unknown = {"name": "target", "status": "UNKNOWN"}
        report = decide(current, [material, unknown], {"status": "UNKNOWN"})
        self.assertEqual(report["status"], "RERUN_REVIEW_REQUIRED")
        self.assertFalse(report["automatic_epoch_authorized"])
        self.assertEqual(
            exit_code({"decision": report}),
            10,
        )
        report = decide(current, [unknown], {"status": "CURRENT"})
        self.assertEqual(report["status"], "UNKNOWN")
        report = decide(current, [history], {"status": "CURRENT"})
        self.assertEqual(report["status"], "NO_RERUN_TRIGGER")


if __name__ == "__main__":
    unittest.main()
