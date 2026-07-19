from __future__ import annotations

import json
import os
import tempfile
import unittest
import base64
from pathlib import Path

from harness.canary_store import CanaryError, CanaryStore
from harness.browser_policy import browser_refusal
from harness.ledger import DuplicateExecutionError, ExecutionLedger, write_once
from harness.limits import (
    REQUEST_BYTES,
    SCHEMA_DEPTH,
    LimitExceeded,
    enforce_bytes,
    enforce_schema_depth,
)
from harness.process_control import (
    Completed,
    ProcessControlError,
    cleanup_labeled_containers,
    scrubbed_environment,
)
from harness.qualification import cq_009
from harness.redaction import REDACTED, RedactionError, redact
from harness.watchdog import revoke_container


def completed(
    argv: list[str],
    *,
    returncode: int = 0,
    stdout: bytes = b"",
    stderr: bytes = b"",
) -> Completed:
    return Completed(tuple(argv), returncode, stdout, stderr, False, 0.0)


class SafetyControlTests(unittest.TestCase):
    def test_canary_identity_and_tamper_detection(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            store = CanaryStore(Path(temporary) / "canaries", "run-1", "nonce-1")
            record = store.write_once("effect.json", {"count": 1})
            self.assertEqual(record["value"], {"count": 1})
            with self.assertRaises(FileExistsError):
                store.write_once("effect.json", {"count": 2})
            path = store.path_for("effect.json")
            data = json.loads(path.read_text(encoding="utf-8"))
            data["value"]["count"] = 99
            path.write_text(json.dumps(data), encoding="utf-8")
            with self.assertRaises(CanaryError):
                store.read("effect.json")

    def test_canary_rejects_links_and_traversal(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            store = CanaryStore(root / "canaries", "run-1", "nonce-1")
            for name in ("../escape", "/tmp/escape", "nested/name", ".."):
                with self.subTest(name=name), self.assertRaises(CanaryError):
                    store.path_for(name)
            outside = root / "outside"
            outside.write_text("safe", encoding="utf-8")
            os.symlink(outside, store.path_for("linked"))
            with self.assertRaises((CanaryError, FileExistsError)):
                store.write_once("linked", "bad")
            self.assertEqual(outside.read_text(encoding="utf-8"), "safe")

    def test_canary_directory_descriptor_defeats_parent_swap_race(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            parent = Path(temporary)
            outside = parent / "outside"
            outside.mkdir()
            moved = parent / "moved"

            class RacingStore(CanaryStore):
                def _open_relative(self, name: str, flags: int, mode: int | None = None) -> int:
                    self.root.rename(moved)
                    os.symlink(outside, self.root)
                    return super()._open_relative(name, flags, mode)

            store = RacingStore(parent / "canaries", "run-1", "nonce-1")
            try:
                with self.assertRaises(CanaryError):
                    store.write_once("effect", "must-not-escape")
                self.assertFalse((outside / "effect").exists())
                self.assertFalse((moved / "effect").exists())
            finally:
                store.close()

    def test_redaction_is_fail_closed(self) -> None:
        clean = redact(
            {
                "authorization": "Bearer SYNTHETIC_123456",
                "text": "secret=synthetic-secret /Users/example/private",
                "ordinary": "kept",
            }
        )
        self.assertEqual(clean["authorization"], REDACTED)
        self.assertEqual(clean["ordinary"], "kept")
        self.assertNotIn("/Users/example", clean["text"])
        with self.assertRaises(RedactionError):
            redact(b"\xff")
        with self.assertRaises(RedactionError):
            redact({"large": "x" * (256 * 1024 + 1)})
        encoded = base64.b64encode(b"token=synthetic-encoded-secret").decode()
        self.assertEqual(redact(encoded), REDACTED)
        self.assertIn("[CONTROL]", redact("\u001b[31mforged"))

    def test_scrubbed_environment_is_synthetic_and_rejects_secret_keys(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            environment = scrubbed_environment(Path(temporary))
            self.assertEqual(
                set(environment),
                {
                    "PATH",
                    "HOME",
                    "TMPDIR",
                    "XDG_CACHE_HOME",
                    "XDG_CONFIG_HOME",
                    "XDG_STATE_HOME",
                    "LANG",
                    "LC_ALL",
                    "PYTHONHASHSEED",
                },
            )
            self.assertTrue(Path(environment["HOME"]).is_relative_to(Path(temporary).resolve()))
            with self.assertRaises(ProcessControlError):
                scrubbed_environment(Path(temporary), {"SYNTHETIC_TOKEN": "value"})

    def test_active_limit_boundaries(self) -> None:
        self.assertEqual(len(enforce_bytes(b"x" * REQUEST_BYTES, REQUEST_BYTES, "request")), REQUEST_BYTES)
        with self.assertRaises(LimitExceeded):
            enforce_bytes(b"x" * (REQUEST_BYTES + 1), REQUEST_BYTES, "request")
        value: object = "leaf"
        for _ in range(SCHEMA_DEPTH):
            value = {"next": value}
        enforce_schema_depth(value)
        value = {"next": value}
        with self.assertRaises(LimitExceeded):
            enforce_schema_depth(value)

    def test_ledger_rejects_duplicate_and_replayed_result(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            root = Path(temporary)
            ledger = ExecutionLedger(root / "ledger")
            ledger.claim("run", "case")
            with self.assertRaises(DuplicateExecutionError):
                ledger.claim("run", "case")
            result = root / "results" / "case.json"
            write_once(result, b"one")
            with self.assertRaises(DuplicateExecutionError):
                write_once(result, b"two")

    def test_browser_disabled_policy_refuses_only_flagged_cases(self) -> None:
        browser_case = {"requires_browser": True}
        plain_case = {"requires_browser": False}
        self.assertTrue(browser_refusal(browser_case, "BROWSER_DISABLED")["unsafe_fallback_refused"])
        self.assertIsNone(browser_refusal(plain_case, "BROWSER_DISABLED"))

    def test_cleanup_fails_when_container_enumeration_fails(self) -> None:
        with tempfile.TemporaryDirectory() as temporary:
            def failed_list(arguments: list[str], *, cwd: Path) -> Completed:
                return completed(arguments, returncode=125, stderr=b"synthetic list failure")

            with self.assertRaises(ProcessControlError):
                cleanup_labeled_containers(
                    "run-1",
                    Path(temporary),
                    docker_call=failed_list,
                )

    def test_cleanup_fails_when_container_removal_fails(self) -> None:
        calls = 0

        def failed_removal(arguments: list[str], *, cwd: Path) -> Completed:
            nonlocal calls
            calls += 1
            if calls == 1:
                return completed(arguments, stdout=b"container-1\n")
            return completed(arguments, returncode=1, stderr=b"synthetic remove failure")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ProcessControlError):
                cleanup_labeled_containers(
                    "run-1",
                    Path(temporary),
                    docker_call=failed_removal,
                )

    def test_cleanup_fails_when_final_container_listing_has_residue(self) -> None:
        calls = 0

        def stale_final_listing(arguments: list[str], *, cwd: Path) -> Completed:
            nonlocal calls
            calls += 1
            if calls == 1:
                return completed(arguments)
            return completed(arguments, stdout=b"late-container\n")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ProcessControlError):
                cleanup_labeled_containers(
                    "run-1",
                    Path(temporary),
                    docker_call=stale_final_listing,
                )

    def test_cq009_fails_when_post_cleanup_enumeration_fails(self) -> None:
        calls = 0

        def failed_post_cleanup_list(arguments: list[str], *, cwd: Path) -> Completed:
            nonlocal calls
            calls += 1
            if calls == 3:
                return completed(arguments, returncode=125, stderr=b"synthetic CQ009 failure")
            return completed(arguments)

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ProcessControlError):
                cq_009(
                    Path(temporary) / "cq009",
                    "run-1",
                    docker_call=failed_post_cleanup_list,
                )

    def test_watchdog_fails_when_cleanup_enumeration_fails(self) -> None:
        calls = 0

        def failed_watchdog_list(arguments: list[str], *, cwd: Path) -> Completed:
            nonlocal calls
            calls += 1
            if calls == 1:
                return completed(arguments)
            return completed(arguments, returncode=125, stderr=b"synthetic watchdog failure")

        with tempfile.TemporaryDirectory() as temporary:
            with self.assertRaises(ProcessControlError):
                revoke_container(
                    "container-1",
                    "run-1",
                    Path(temporary),
                    docker_call=failed_watchdog_list,
                )


if __name__ == "__main__":
    unittest.main()
