"""Gate 1B containment qualification; no suite attack executes before this passes."""

from __future__ import annotations

import base64
import contextlib
import hashlib
import json
import os
import platform
import re
import secrets
import shutil
import signal
import socket
import subprocess
import sys
import threading
import time
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any, cast

from harness.browser_policy import browser_refusal
from harness.canary_store import CanaryError, CanaryStore
from harness.ledger import DuplicateExecutionError, ExecutionLedger, write_once
from harness.limits import (
    DECOMPRESSED_BYTES,
    REDIRECTS,
    REQUEST_BYTES,
    RESPONSE_BYTES,
    SCHEMA_DEPTH,
    LimitExceeded,
    enforce_bytes,
    enforce_redirects,
    enforce_schema_depth,
)
from harness.process_control import (
    Completed,
    ProcessControlError,
    cleanup_labeled_containers,
    docker,
    require_successful_empty_listing,
    safe_container_arguments,
    scrubbed_environment,
    trusted_supervisor_environment,
)
from harness.redaction import MAX_EVIDENCE_BYTES, RedactionError, redact
from harness.schema_validation import SchemaValidationError, load_json, validate

ROOT = Path(__file__).resolve().parents[1]
IMAGE = "mcp-trust-live-batch:20260628"
QUALIFICATION_VERSION = "MHAI-CONTAINMENT-1"
QUALIFICATION_LABEL_SUFFIXES = ("", "-04", "-05", "-06", "-08", "-09", "-11", "-12")


class QualificationError(RuntimeError):
    """A containment qualification could not satisfy its exact oracle."""


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def digest_paths(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def harness_digest() -> str:
    paths = [
        path
        for directory in (
            ROOT / "harness",
            ROOT / "suite_impl",
            ROOT / "fixtures" / "processes",
        )
        for path in directory.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and not path.name.endswith(".pyc")
    ]
    paths.extend(
        [
            ROOT / "cases.json",
            ROOT / "SAFETY-BOUNDARY.md",
            ROOT / "CONTAINMENT-QUALIFICATION.md",
            ROOT / "schemas" / "qualification.schema.json",
            ROOT / "schemas" / "result.schema.json",
            ROOT / "schemas" / "run-manifest.schema.json",
            ROOT / "schemas" / "test-case.schema.json",
            ROOT / "schemas" / "closure-epoch-open.schema.json",
            ROOT / "schemas" / "closure-epoch-close.schema.json",
        ]
    )
    return digest_paths(paths)


def require_cached_image(run_root: Path) -> tuple[str, str]:
    inspected = docker(
        ["image", "inspect", "--format", "{{.Id}} {{.RepoDigests}}", IMAGE],
        cwd=run_root,
    )
    if inspected.returncode != 0:
        raise QualificationError(f"required cached image unavailable: {IMAGE}")
    identity = inspected.stdout.decode().strip()
    if not identity:
        raise QualificationError("cached image identity was empty")
    server = docker(["version", "--format", "{{.Server.Version}}"], cwd=run_root)
    if server.returncode != 0:
        raise QualificationError("container runtime unavailable")
    return identity, server.stdout.decode().strip()


def current_runtime(run_root: Path) -> dict[str, str]:
    image_identity, docker_server = require_cached_image(run_root)
    return {
        "os": platform.platform(),
        "python": platform.python_version(),
        "container_server": docker_server,
        "container_image": image_identity,
    }


def verify_qualification_cleanup(
    run_id: str,
    run_root: Path,
    *,
    docker_call: Callable[..., Completed] = docker,
) -> dict[str, int]:
    removed = 0
    for suffix in QUALIFICATION_LABEL_SUFFIXES:
        label = f"{run_id}{suffix}"
        removed += len(
            cleanup_labeled_containers(
                label,
                run_root,
                docker_call=docker_call,
            )
        )
        for resource in ("network", "volume"):
            listed = docker_call(
                [
                    resource,
                    "ls",
                    "-q",
                    "--filter",
                    f"label=mhai.run_id={label}",
                ],
                cwd=run_root,
            )
            require_successful_empty_listing(listed, f"{resource}s for {label}")
    return {
        "labels_verified": len(QUALIFICATION_LABEL_SUFFIXES),
        "containers_removed": removed,
    }


def validate_qualification_contract(receipt: dict[str, Any]) -> None:
    validate(receipt, load_json(ROOT / "schemas" / "qualification.schema.json"))
    expected = [f"CQ-{index:03d}" for index in range(1, 13)]
    actual = [item["check_id"] for item in receipt["checks"]]
    if actual != expected or len(set(actual)) != 12:
        raise SchemaValidationError(
            f"$.checks: expected exactly ordered unique identities {expected}, got {actual}"
        )
    all_passed = all(item["result"] == "PASS" for item in receipt["checks"])
    if (receipt["result"] == "PASS") != all_passed:
        raise SchemaValidationError("$.result: must equal the aggregate of all CQ results")
    try:
        started = datetime.fromisoformat(receipt["started_at"].replace("Z", "+00:00"))
        finished = datetime.fromisoformat(receipt["finished_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaValidationError(f"$.started_at/finished_at: invalid timestamp: {exc}") from exc
    if started.utcoffset() is None or finished.utcoffset() is None or finished < started:
        raise SchemaValidationError("$.started_at/finished_at: ordered timezone offsets required")
    cq12 = receipt["checks"][-1]
    if receipt["browser_mode"] == "BROWSER_DISABLED":
        observations = cq12["observations"]
        if not observations or not observations[0].get("all_browser_cases_refused"):
            raise SchemaValidationError(
                "$.browser_mode: BROWSER_DISABLED requires exercised case-routing refusal"
            )


def aggregate_qualification_result(
    checks: list[dict[str, Any]],
    *,
    cleanup_verified: bool,
) -> str:
    if cleanup_verified and all(item["result"] == "PASS" for item in checks):
        return "PASS"
    return "ERROR"


def receipt_runtime_is_current(receipt: dict[str, Any], run_root: Path) -> bool:
    return receipt["runtime"] == current_runtime(run_root)


def binding_is_current(
    receipt_digest: str,
    receipt_runtime: dict[str, str],
    expected_digest: str,
    expected_runtime: dict[str, str],
) -> bool:
    return receipt_digest == expected_digest and receipt_runtime == expected_runtime


def atomic_json(path: Path, value: Any) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    clean = redact(value)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("w", encoding="utf-8") as handle:
        json.dump(clean, handle, indent=2, sort_keys=True)
        handle.write("\n")
        handle.flush()
        os.fsync(handle.fileno())
    os.chmod(temporary, 0o600)
    os.replace(temporary, path)


def check(check_id: str, function: Callable[[], list[dict[str, Any]]]) -> dict[str, Any]:
    try:
        observations = redact(function())
        return {"check_id": check_id, "result": "PASS", "observations": observations}
    except Exception as exc:  # receipt must capture and stop safely
        return {
            "check_id": check_id,
            "result": "ERROR",
            "observations": [{"error_type": type(exc).__name__, "detail": str(exc)}],
        }


def cq_001(root: Path, run_id: str, nonce: str) -> list[dict[str, Any]]:
    store = CanaryStore(root / "canaries", run_id, nonce)
    written = store.write_once("positive.json", {"effect": "qualified"})
    if written["value"]["effect"] != "qualified" or not store.absent("negative.json"):
        raise QualificationError("canary positive/negative sensor mismatch")
    path = store.path_for("positive.json")
    path.write_text('{"tampered":true}\n', encoding="utf-8")
    try:
        store.read("positive.json")
    except (CanaryError, json.JSONDecodeError):
        tamper_detected = True
    else:
        tamper_detected = False
    if not tamper_detected:
        raise QualificationError("canary tamper was not detected")
    return [{"positive_detected": True, "negative_absent": True, "tamper_detected": True}]


def cq_002(root: Path, run_id: str, nonce: str) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    canary_root = root / "paths"
    outside = root / "outside"
    outside.mkdir()
    store = CanaryStore(canary_root, run_id, nonce)
    rejected: list[str] = []
    for name in ("../escape", "/absolute", "nested/name", ".."):
        try:
            store.write_once(name, "bad")
        except CanaryError:
            rejected.append(name)
    outside_target = outside / "target"
    outside_target.write_text("unchanged", encoding="utf-8")
    os.symlink(outside_target, store.path_for("symlink"))
    try:
        store.write_once("symlink", "bad")
    except (CanaryError, FileExistsError):
        rejected.append("symlink")
    store.write_once("linked", "safe")
    os.link(store.path_for("linked"), outside / "hardlink")
    try:
        store.read("linked")
    except CanaryError:
        rejected.append("hardlink")
    original = store.root
    moved = root / "paths-moved"
    original.rename(moved)
    os.symlink(outside, original)
    try:
        store.write_once("swapped", "bad")
    except CanaryError:
        rejected.append("root-swap")
    expected = {"../escape", "/absolute", "nested/name", "..", "symlink", "hardlink", "root-swap"}
    if set(rejected) != expected or outside_target.read_text(encoding="utf-8") != "unchanged":
        raise QualificationError(f"path boundary mismatch: {rejected}")
    original.unlink()
    moved.rename(original)
    store.close()

    race_root = root / "race-root"
    race_moved = root / "race-root-pinned"

    class RacingStore(CanaryStore):
        raced = False

        def _open_relative(self, name: str, flags: int, mode: int | None = None) -> int:
            if not self.raced and flags & os.O_WRONLY:
                self.raced = True
                self.root.rename(race_moved)
                os.symlink(outside, self.root)
            return super()._open_relative(name, flags, mode)

    racing = RacingStore(race_root, run_id, nonce)
    try:
        try:
            racing.write_once("race", "must-not-escape")
        except CanaryError:
            rejected.append("post-validation-root-race")
        else:
            raise QualificationError("post-validation root replacement was not rejected")
        if (outside / "race").exists() or (race_moved / "race").exists():
            raise QualificationError("post-validation race left a canary file")
    finally:
        racing.close()
        if race_root.is_symlink():
            race_root.unlink()
        if race_moved.exists():
            race_moved.rename(race_root)
    expected.add("post-validation-root-race")
    if set(rejected) != expected:
        raise QualificationError(f"path boundary race mismatch: {rejected}")
    return [
        {
            "rejected": sorted(rejected),
            "outside_unchanged": True,
            "directory_descriptor_pinned": True,
        }
    ]


class _NonceListener:
    def __init__(self, nonce: str) -> None:
        self.nonce = nonce
        self.socket = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
        self.socket.bind(("127.0.0.1", 0))
        self.socket.listen(1)
        self.port = self.socket.getsockname()[1]
        self.hit = False
        self.thread = threading.Thread(target=self._serve, daemon=True)

    def _serve(self) -> None:
        self.socket.settimeout(5)
        try:
            connection, _ = self.socket.accept()
            with connection:
                self.hit = connection.recv(128).decode(errors="replace") == self.nonce
        except TimeoutError:
            pass

    def __enter__(self) -> _NonceListener:
        self.thread.start()
        return self

    def __exit__(self, *_args: object) -> None:
        self.socket.close()
        self.thread.join(timeout=1)


def cq_003(root: Path, run_id: str, image: str) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    nonce = secrets.token_hex(12)
    with _NonceListener(nonce) as unrelated:
        code = r"""
const net = require("net");
const dns = require("dns");
const hostPort = Number(process.argv[1]);
const nonce = process.argv[2];
function connect(host, port, send) {
  return new Promise((resolve) => {
    const socket = net.createConnection({host, port});
    const timer = setTimeout(() => { socket.destroy(); resolve(false); }, 400);
    socket.on("connect", () => { if (send) socket.write(send); clearTimeout(timer); socket.end(); resolve(true); });
    socket.on("error", () => { clearTimeout(timer); resolve(false); });
  });
}
(async () => {
  const server = net.createServer((socket) => socket.once("data", (data) => socket.end(data)));
  await new Promise((resolve) => server.listen(0, "127.0.0.1", resolve));
  const port = server.address().port;
  const internal = await connect("127.0.0.1", port, nonce);
  const probes = {
    unrelated_loopback: await connect("127.0.0.1", hostPort, nonce),
    other_loopback: await connect("127.0.0.1", 9, nonce),
    metadata: await connect("169.254.169.254", 80, nonce),
    public_ip: await connect("1.1.1.1", 53, nonce)
  };
  const dnsResult = await new Promise((resolve) => dns.lookup("example.invalid", (err) => resolve(!err)));
  probes.dns = dnsResult;
  server.close();
  console.log(JSON.stringify({internal, probes, env_keys: Object.keys(process.env).sort()}));
})().catch((error) => { console.error(error); process.exit(2); });
"""
        arguments = safe_container_arguments(
            name=f"mhai-cq003-{run_id[-8:]}",
            run_id=run_id,
            image=image,
            command=["node", "-e", code, str(unrelated.port), nonce],
        )
        completed = docker(arguments, cwd=root, timeout_seconds=15)
    if completed.returncode != 0:
        raise QualificationError(
            f"network probe return={completed.returncode} "
            f"stdout={completed.stdout.decode(errors='replace')!r} "
            f"stderr={completed.stderr.decode(errors='replace')!r}"
        )
    payload = json.loads(completed.stdout)
    if not payload["internal"] or any(payload["probes"].values()) or unrelated.hit:
        raise QualificationError(f"network boundary mismatch: {payload}")
    forbidden_env = [
        key
        for key in payload["env_keys"]
        if any(marker in key.upper() for marker in ("PROXY", "TOKEN", "SECRET", "DOCKER", "CREDENTIAL"))
    ]
    if forbidden_env:
        raise QualificationError(f"container inherited forbidden environment keys: {forbidden_env}")
    return [{"internal_nonce_exchange": True, "denied": payload["probes"], "outside_hit": False}]


def _wait_for(path: Path, timeout: float = 8) -> None:
    deadline = time.monotonic() + timeout
    while not path.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not path.exists():
        raise QualificationError(f"timed out waiting for {path.name}")


def _watchdog_trial(root: Path, run_id: str, image: str, *, controller_death: bool) -> list[dict[str, Any]]:
    identity = root / "identity.json"
    lease = root / "lease.json"
    receipt = root / "watchdog.json"
    fixture = ROOT / "fixtures" / "processes" / "delayed_tree.js"
    environment = trusted_supervisor_environment(root)
    watchdog = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "harness.watchdog",
            "--run-root",
            str(root),
            "--run-id",
            run_id,
            "--identity",
            str(identity),
            "--lease",
            str(lease),
            "--receipt",
            str(receipt),
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    controller = subprocess.Popen(
        [
            sys.executable,
            "-m",
            "harness.container_controller",
            "--run-root",
            str(root),
            "--run-id",
            run_id,
            "--container-name",
            f"mhai-watch-{run_id[-8:]}",
            "--image",
            image,
            "--identity",
            str(identity),
            "--lease",
            str(lease),
            "--fixture",
            str(fixture),
        ],
        cwd=ROOT,
        env=environment,
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    unrelated: subprocess.Popen[bytes] | None = None
    stop_started = 0.0
    try:
        _wait_for(identity)
        _wait_for(lease)
        if controller_death:
            os.killpg(controller.pid, signal.SIGKILL)
            controller.wait(timeout=2)
        else:
            os.killpg(controller.pid, signal.SIGSTOP)
            stop_started = time.monotonic()
            lease.unlink(missing_ok=True)
        unrelated = subprocess.Popen(
            ["/bin/sleep", "5"],
            env=scrubbed_environment(root / "unrelated-after-loss"),
            stdin=subprocess.DEVNULL,
            stdout=subprocess.DEVNULL,
            stderr=subprocess.DEVNULL,
            close_fds=True,
            start_new_session=True,
        )
        watchdog_return = watchdog.wait(timeout=10)
        stop_elapsed = time.monotonic() - stop_started if stop_started else None
        _wait_for(receipt, timeout=1)
        watchdog_receipt = json.loads(receipt.read_text(encoding="utf-8"))
        unrelated_survived = unrelated.poll() is None
        time.sleep(3)
        delayed = root / "container-canary" / "delayed.json"
        remaining = docker(
            ["ps", "-aq", "--filter", f"label=mhai.run_id={run_id}"],
            cwd=root,
        )
        require_successful_empty_listing(remaining, f"watchdog containers for {run_id}")
        if (
            watchdog_return != 0
            or watchdog_receipt.get("result") != "PASS"
            or delayed.exists()
            or not unrelated_survived
            or (stop_elapsed is not None and stop_elapsed > 2)
        ):
            raise QualificationError(
                f"watchdog mismatch: return={watchdog_return} receipt={watchdog_receipt} "
                f"delayed={delayed.exists()} unrelated={unrelated_survived}"
            )
        return [
            {
                "controller_mode": "death" if controller_death else "emergency-stop",
                "watchdog": "PASS",
                "delayed_window_seconds": 3,
                "delayed_canary_absent": True,
                "unrelated_process_survived": True,
                "pid_reuse_probe_started_after_controller_loss": True,
                "emergency_stop_seconds": stop_elapsed,
                "immutable_container_identity": watchdog_receipt["container_id"],
            }
        ]
    finally:
        for process in (controller, watchdog, unrelated):
            if process is not None and process.poll() is None:
                with contextlib.suppress(ProcessLookupError):
                    os.killpg(process.pid, signal.SIGKILL)
                process.wait(timeout=2)
        cleanup_labeled_containers(run_id, root)


def cq_006(root: Path, run_id: str, image: str) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    fixture = root / "fixture-writable"
    trusted = root / "trusted-results"
    fixture.mkdir(mode=0o777)
    trusted.mkdir(mode=0o700)
    forged = {
        "case_id": "RT-001",
        "result": "PASS",
        "case_definition_digest": "0" * 64,
        "escape": "\u001b[31mPASS",
        "nested": {"authorization": "Bearer SYNTHETIC_FORGED_TOKEN"},
    }
    code = """
const fs = require("fs");
let trustedWrite = true;
try { fs.writeFileSync("/trusted/result.json", JSON.stringify({result:"PASS"})); }
catch (_) { trustedWrite = false; }
fs.writeFileSync("/canary/forged.json", JSON.stringify({
  case_id:"RT-001", result:"PASS", evidence_pointer:"../trusted-results/oracle.json"
}));
console.log(JSON.stringify({trusted_write: trustedWrite, forged_written: true}));
"""
    contained = docker(
        safe_container_arguments(
            name=f"mhai-cq006-{run_id[-8:]}",
            run_id=run_id,
            image=image,
            command=["node", "-e", code],
            canary_mount=fixture,
        ),
        cwd=root,
    )
    if contained.returncode != 0:
        raise QualificationError(contained.stderr.decode(errors="replace"))
    contained_result = json.loads(contained.stdout)
    if contained_result["trusted_write"] or not (fixture / "forged.json").exists():
        raise QualificationError("contained forged-result control did not exercise separation")
    observation = cast(
        dict[str, Any],
        redact({"kind": "fixture-output", "payload": forged}),
    )
    redacted_payload = cast(dict[str, Any], observation["payload"])
    redacted_nested = cast(dict[str, Any], redacted_payload["nested"])
    forged_nested = cast(dict[str, Any], forged["nested"])
    if redacted_nested["authorization"] == forged_nested["authorization"]:
        raise QualificationError("forged sensitive value was not redacted")
    if any(trusted.iterdir()):
        raise QualificationError("fixture created a trusted result")

    def accept_pointer(pointer: str) -> bool:
        if not pointer or Path(pointer).is_absolute() or ".." in Path(pointer).parts:
            return False
        candidate = (trusted / pointer).resolve()
        try:
            candidate.relative_to(trusted.resolve())
        except ValueError:
            return False
        return candidate.is_file()

    if accept_pointer("../fixture-writable/forged.json"):
        raise QualificationError("forged evidence pointer escaped trusted storage")
    atomic_json(trusted / "oracle.json", {"oracle": "trusted", "fixture_result_accepted": False})
    if not accept_pointer("oracle.json"):
        raise QualificationError("trusted evidence pointer negative control failed")
    return [
        {
            "contained_fixture_write": True,
            "contained_trusted_write": False,
            "fixture_result_accepted": False,
            "forged_evidence_pointer_rejected": True,
            "trusted_result_count": 1,
        }
    ]


def cq_007() -> list[dict[str, Any]]:
    positive = {
        "authorization": "Bearer SYNTHETIC_TOKEN_123456",
        "cookie": "cookie=sessionvalue",
        "text": "secret=synthetic-secret /Users/example/private",
        "private_key": "-----BEGIN PRIVATE KEY-----",
        "encoded": base64.b64encode(b"token=synthetic-encoded-secret").decode(),
        "percent_encoded": "token%3Dsynthetic-percent-secret",
        "terminal": "\u001b[31mforged-pass",
    }
    clean = redact(positive)
    encoded = json.dumps(clean)
    if (
        "SYNTHETIC_TOKEN_123456" in encoded
        or "/Users/example" in encoded
        or "synthetic-encoded-secret" in encoded
        or clean["encoded"] != "[REDACTED_SYNTHETIC_SECRET]"
        or clean["percent_encoded"] != "[REDACTED_SYNTHETIC_SECRET]"
        or "[CONTROL]" not in clean["terminal"]
    ):
        raise QualificationError("redaction positive control leaked")
    ordinary = {"message": "ordinary diagnostic", "count": 3}
    if redact(ordinary) != ordinary:
        raise QualificationError("redaction negative control changed ordinary fields")
    failures = 0
    for hostile in (
        b"\xff",
        {"deep": [[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[[["x"]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]]},
        {"large": "x" * (MAX_EVIDENCE_BYTES + 1)},
    ):
        try:
            redact(hostile)
        except RedactionError:
            failures += 1
    if failures != 3:
        raise QualificationError("fail-closed redaction controls did not all fail")
    return [
        {
            "synthetic_patterns_redacted": True,
            "encoded_patterns_redacted": True,
            "control_characters_removed": True,
            "ordinary_preserved": True,
            "fail_closed": 3,
        }
    ]


def cq_008(root: Path, run_id: str, image: str) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    canary = root / "resource-canary"
    canary.mkdir(mode=0o777)
    name = f"mhai-cq008-{run_id[-8:]}"
    arguments = safe_container_arguments(
        name=name,
        run_id=run_id,
        image=image,
        command=["node", "-e", "setInterval(() => {}, 1000)"],
        canary_mount=canary,
        detached=True,
    )
    launched = docker(arguments, cwd=root)
    if launched.returncode != 0:
        raise QualificationError(launched.stderr.decode(errors="replace"))
    container_id = launched.stdout.decode().strip()
    try:
        inspected = docker(["inspect", container_id], cwd=root)
        details = json.loads(inspected.stdout)[0]
        host = details["HostConfig"]
        config = details["Config"]
        expected = {
            "network_none": host["NetworkMode"] == "none",
            "readonly_root": host["ReadonlyRootfs"] is True,
            "pids_16": host["PidsLimit"] == 16,
            "memory_256m": host["Memory"] == 256 * 1024 * 1024,
            "cpu_half": host["NanoCpus"] == 500_000_000,
            "caps_dropped": host["CapDrop"] == ["ALL"],
            "no_new_privileges": "no-new-privileges" in (host["SecurityOpt"] or []),
            "non_root": config["User"] == "65534:65534",
            "only_declared_bind": len(details["Mounts"]) == 1
            and details["Mounts"][0]["Destination"] == "/canary",
            "nofile_64": any(
                item["Name"] == "nofile" and item["Soft"] == 64 and item["Hard"] == 64
                for item in host["Ulimits"]
            ),
            "fsize_8m": any(
                item["Name"] == "fsize"
                and item["Soft"] == 8 * 1024 * 1024
                and item["Hard"] == 8 * 1024 * 1024
                for item in host["Ulimits"]
            ),
        }
        if not all(expected.values()):
            raise QualificationError(f"container flag mismatch: {expected}")
        forbidden = docker(
            ["exec", container_id, "node", "-e", "require('fs').writeFileSync('/forbidden','x')"],
            cwd=root,
        )
        allowed = docker(
            [
                "exec",
                container_id,
                "node",
                "-e",
                "require('fs').writeFileSync('/canary/allowed','x')",
            ],
            cwd=root,
        )
        file_at_limit = docker(
            [
                "exec",
                container_id,
                "node",
                "-e",
                "require('fs').writeFileSync('/canary/at-limit',Buffer.alloc(8*1024*1024))",
            ],
            cwd=root,
        )
        file_over_limit = docker(
            [
                "exec",
                container_id,
                "node",
                "-e",
                "require('fs').writeFileSync('/canary/over-limit',Buffer.alloc(8*1024*1024+1))",
            ],
            cwd=root,
        )
        if (
            forbidden.returncode == 0
            or allowed.returncode != 0
            or file_at_limit.returncode != 0
            or file_over_limit.returncode == 0
            or not (canary / "allowed").exists()
        ):
            raise QualificationError(
                "active filesystem ceiling probes disagreed: "
                f"forbidden={forbidden.returncode}, allowed={allowed.returncode}, "
                f"at_limit={file_at_limit.returncode}, over_limit={file_over_limit.returncode}, "
                f"allowed_exists={(canary / 'allowed').exists()}, "
                f"at_size={(canary / 'at-limit').stat().st_size if (canary / 'at-limit').exists() else None}, "
                f"over_size={(canary / 'over-limit').stat().st_size if (canary / 'over-limit').exists() else None}"
            )

        def byte_boundary(limit: int, label: str) -> list[bool]:
            outcomes: list[bool] = []
            for size in (limit - 1, limit, limit + 1):
                try:
                    enforce_bytes(b"x" * size, limit, label)
                    outcomes.append(True)
                except LimitExceeded:
                    outcomes.append(False)
            return outcomes

        byte_outcomes = {
            "request": byte_boundary(REQUEST_BYTES, "request"),
            "response": byte_boundary(RESPONSE_BYTES, "response"),
            "decompressed": byte_boundary(DECOMPRESSED_BYTES, "decompressed"),
        }
        redirect_outcomes = []
        for count in (REDIRECTS - 1, REDIRECTS, REDIRECTS + 1):
            try:
                enforce_redirects(count)
                redirect_outcomes.append(True)
            except LimitExceeded:
                redirect_outcomes.append(False)
        depth_outcomes = []
        for depth in (SCHEMA_DEPTH - 1, SCHEMA_DEPTH, SCHEMA_DEPTH + 1):
            value: Any = "leaf"
            for _ in range(depth):
                value = {"next": value}
            try:
                enforce_schema_depth(value)
                depth_outcomes.append(True)
            except LimitExceeded:
                depth_outcomes.append(False)
        all_outcomes = [*byte_outcomes.values(), redirect_outcomes, depth_outcomes]
        if any(outcome != [True, True, False] for outcome in all_outcomes):
            raise QualificationError(
                f"active protocol boundary mismatch: {byte_outcomes}, "
                f"redirects={redirect_outcomes}, depth={depth_outcomes}"
            )
        return [
            {
                "runtime_flags": expected,
                "file_size": {"at_limit": True, "over_limit_rejected": True},
                "byte_boundaries": byte_outcomes,
                "redirect_boundaries": redirect_outcomes,
                "schema_depth_boundaries": depth_outcomes,
            }
        ]
    finally:
        removed = docker(["rm", "-f", container_id], cwd=root)
        if removed.returncode != 0:
            raise ProcessControlError(
                f"CQ-008 container removal failed for {container_id}: "
                f"{removed.stderr.decode(errors='replace')}"
            )


def cq_009(
    root: Path,
    run_id: str,
    *,
    docker_call: Callable[..., Completed] = docker,
) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    retained = root / "retained-positive-control"
    retained.write_text("retained", encoding="utf-8")
    retained_detected = retained.exists()

    process = subprocess.Popen(
        ["/bin/sleep", "5"],
        env=scrubbed_environment(root / "process-env"),
        stdin=subprocess.DEVNULL,
        stdout=subprocess.DEVNULL,
        stderr=subprocess.DEVNULL,
        close_fds=True,
        start_new_session=True,
    )
    process_detected = process.poll() is None
    os.killpg(process.pid, signal.SIGTERM)
    process.wait(timeout=2)
    process_clean = process.poll() is not None

    listener = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    listener.bind(("127.0.0.1", 0))
    listener.listen(1)
    port = listener.getsockname()[1]
    listener_detected = listener.fileno() >= 0
    listener.close()
    probe = socket.socket(socket.AF_INET, socket.SOCK_STREAM)
    probe.settimeout(0.2)
    listener_clean = probe.connect_ex(("127.0.0.1", port)) != 0
    probe.close()

    descriptor_path = root / "descriptor"
    descriptor_path.write_text("open", encoding="utf-8")
    descriptor = descriptor_path.open("rb")
    descriptor_detected = not descriptor.closed
    descriptor.close()
    descriptor_clean = descriptor.closed

    profile = root / "browser-profile"
    profile.mkdir()
    profile_detected = profile.exists()
    profile.rmdir()
    profile_clean = not profile.exists()

    delayed = root / "delayed-action"
    timer = threading.Timer(0.2, lambda: delayed.write_text("late", encoding="utf-8"))
    timer.start()
    timer.cancel()
    timer.join(timeout=1)
    time.sleep(0.3)
    delayed_clean = not delayed.exists()

    sacrificial = root / "temporary-path"
    sacrificial.mkdir()
    (sacrificial / "file").write_text("temporary", encoding="utf-8")
    shutil.rmtree(sacrificial)
    temporary_clean = not sacrificial.exists()

    retained.unlink()
    removed = cleanup_labeled_containers(
        run_id,
        root,
        docker_call=docker_call,
    )
    remaining = docker_call(
        ["ps", "-aq", "--filter", f"label=mhai.run_id={run_id}"],
        cwd=root,
    )
    require_successful_empty_listing(remaining, f"CQ-009 containers for {run_id}")
    network_remaining = docker_call(
        ["network", "ls", "-q", "--filter", f"label=mhai.run_id={run_id}"],
        cwd=root,
    )
    require_successful_empty_listing(network_remaining, f"CQ-009 networks for {run_id}")
    volume_remaining = docker_call(
        ["volume", "ls", "-q", "--filter", f"label=mhai.run_id={run_id}"],
        cwd=root,
    )
    require_successful_empty_listing(volume_remaining, f"CQ-009 volumes for {run_id}")
    checks = {
        "retained_artifact_detected": retained_detected,
        "process_detected": process_detected,
        "process_clean": process_clean,
        "listener_detected": listener_detected,
        "listener_clean": listener_clean,
        "descriptor_detected": descriptor_detected,
        "descriptor_clean": descriptor_clean,
        "profile_detected": profile_detected,
        "profile_clean": profile_clean,
        "delayed_action_clean": delayed_clean,
        "temporary_paths_clean": temporary_clean,
        "containers_mounts_namespaces_clean": True,
        "networks_clean": True,
        "volumes_clean": True,
    }
    if not all(checks.values()):
        raise QualificationError("cleanup positive or negative control failed")
    return [{**checks, "containers_removed": len(removed), "clean": True}]


def cq_010(root: Path, digest: str, runtime: dict[str, str]) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    ledger = ExecutionLedger(root / "ledger")
    ledger.claim("qualification-run", "CQ-010")
    try:
        ledger.claim("qualification-run", "CQ-010")
    except DuplicateExecutionError:
        duplicate_rejected = True
    else:
        duplicate_rejected = False
    replay = root / "trusted-results" / "CQ-010.json"
    write_once(replay, b'{"result":"PASS"}\n')
    try:
        write_once(replay, b'{"result":"PASS"}\n')
    except DuplicateExecutionError:
        replay_rejected = True
    else:
        replay_rejected = False
    current_accepted = binding_is_current(digest, runtime, digest, runtime)
    stale_digest_rejected = not binding_is_current("0" * 64, runtime, digest, runtime)
    changed_runtime = dict(runtime)
    changed_runtime["container_image"] = "sha256:" + ("0" * 64)
    stale_runtime_rejected = not binding_is_current(digest, changed_runtime, digest, runtime)
    if (
        not duplicate_rejected
        or not replay_rejected
        or not current_accepted
        or not stale_digest_rejected
        or not stale_runtime_rejected
    ):
        raise QualificationError("duplicate/stale qualification rejection failed")
    return [
        {
            "duplicate_rejected": True,
            "replay_rejected": True,
            "current_binding_accepted": True,
            "stale_digest_rejected": True,
            "stale_runtime_rejected": True,
        }
    ]


def cq_011(root: Path, run_id: str, image: str) -> list[dict[str, Any]]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    code = r"""
const fs = require("fs");
function read(path) { try { return fs.readFileSync(path, "utf8").trim(); } catch (_) { return null; } }
const descriptors = fs.readdirSync("/proc/self/fd").map(Number).sort((a,b) => a-b).map((fd) => {
  try { return {fd, target: fs.readlinkSync(`/proc/self/fd/${fd}`)}; }
  catch (_) { return {fd, target: "closed-during-inventory"}; }
});
const payload = {
  keys: Object.keys(process.env).sort(),
  environment: process.env,
  cwd: process.cwd(),
  uid: process.getuid(),
  gid: process.getgid(),
  groups: process.getgroups().sort((a,b) => a-b),
  umask: process.umask().toString(8),
  descriptors,
  limits: read("/proc/self/limits"),
  pids_max: read("/sys/fs/cgroup/pids.max"),
  memory_max: read("/sys/fs/cgroup/memory.max"),
  cpu_max: read("/sys/fs/cgroup/cpu.max")
};
console.log(JSON.stringify(payload));
"""
    base = safe_container_arguments(
        name=f"mhai-cq011-safe-{run_id[-8:]}",
        run_id=run_id,
        image=image,
        command=["node", "-e", code],
    )
    safe = docker(base, cwd=root)
    if safe.returncode != 0:
        raise QualificationError(safe.stderr.decode(errors="replace"))
    payload = json.loads(safe.stdout)
    image_inspect = docker(["image", "inspect", image], cwd=root)
    image_config = json.loads(image_inspect.stdout)[0]["Config"]
    expected_keys = {
        item.split("=", 1)[0]
        for item in image_config["Env"]
    } | {
        "HOSTNAME",
        "HOME",
        "TMPDIR",
        "XDG_CACHE_HOME",
        "XDG_CONFIG_HOME",
        "XDG_STATE_HOME",
        "PATH",
        "PWD",
    }
    forbidden = [
        key
        for key in payload["keys"]
        if any(
            marker in key.upper()
            for marker in (
                "TOKEN",
                "SECRET",
                "PASSWORD",
                "COOKIE",
                "AUTH",
                "CREDENTIAL",
                "PROXY",
                "AWS",
                "AZURE",
                "GOOGLE",
                "GITHUB",
                "SSH",
                "DOCKER",
            )
        )
    ]
    expected_environment = {
        "HOME": "/tmp/home",
        "TMPDIR": "/tmp",
        "XDG_CACHE_HOME": "/tmp/cache",
        "XDG_CONFIG_HOME": "/tmp/config",
        "XDG_STATE_HOME": "/tmp/state",
        "PATH": "/usr/local/sbin:/usr/local/bin:/usr/sbin:/usr/bin:/sbin:/bin",
        "PWD": "/tmp",
    }
    descriptor_targets = [item["target"] for item in payload["descriptors"]]
    descriptor_safe = (
        len(descriptor_targets) <= 32
        and not any(
            target.startswith("socket:")
            or ".sock" in target
            or "/Users/" in target
            or "/canary" in target
            for target in descriptor_targets
        )
    )
    limits = payload["limits"] or ""
    limit_checks = {
        "nofile_64": bool(re.search(r"Max open files\s+64\s+64", limits)),
        "pids_16": payload["pids_max"] == "16",
        "memory_256m": payload["memory_max"] == str(256 * 1024 * 1024),
        "cpu_half": payload["cpu_max"] == "50000 100000",
    }
    if (
        forbidden
        or set(payload["keys"]) != expected_keys
        or any(payload["environment"].get(key) != value for key, value in expected_environment.items())
        or payload["cwd"] != "/tmp"
        or payload["uid"] != 65534
        or payload["gid"] != 65534
        or payload["groups"] != [65534]
        or payload["umask"] != "77"
        or not descriptor_safe
        or not all(limit_checks.values())
    ):
        raise QualificationError(f"environment scrub mismatch: {payload}")
    positive = safe_container_arguments(
        name=f"mhai-cq011-control-{run_id[-8:]}",
        run_id=run_id,
        image=image,
        command=["node", "-e", "console.log(JSON.stringify(Object.keys(process.env).sort()))"],
    )
    image_index = positive.index(image)
    positive[image_index:image_index] = ["--env", "MHAI_SYNTHETIC_TOKEN=control"]
    control = docker(positive, cwd=root)
    keys = json.loads(control.stdout)
    if "MHAI_SYNTHETIC_TOKEN" not in keys:
        raise QualificationError("environment inventory positive control failed")
    return [
        {
            "safe_key_names": payload["keys"],
            "forbidden_key_names": [],
            "cwd": payload["cwd"],
            "uid": payload["uid"],
            "gid": payload["gid"],
            "groups": payload["groups"],
            "umask": payload["umask"],
            "descriptor_inventory": payload["descriptors"],
            "descriptor_allowlist_passed": descriptor_safe,
            "process_limit_checks": limit_checks,
            "positive_control_detected": True,
        }
    ]


def cq_012(root: Path, run_id: str, image: str) -> tuple[list[dict[str, Any]], str]:
    root.mkdir(parents=True, exist_ok=True, mode=0o700)
    code = """
const fs = require("fs");
const candidates = ["/usr/bin/chromium", "/usr/bin/google-chrome", "/usr/bin/firefox"];
console.log(JSON.stringify(candidates.filter((path) => fs.existsSync(path))));
"""
    completed = docker(
        safe_container_arguments(
            name=f"mhai-cq012-{run_id[-8:]}",
            run_id=run_id,
            image=image,
            command=["node", "-e", code],
        ),
        cwd=root,
    )
    if completed.returncode != 0:
        raise QualificationError(completed.stderr.decode(errors="replace"))
    browsers = json.loads(completed.stdout)
    if browsers:
        raise QualificationError(
            "a browser exists in the containment image but its isolated launcher is not implemented"
        )
    cases = load_json(ROOT / "cases.json")
    browser_cases = [case for case in cases if case["requires_browser"]]
    non_browser_cases = [case for case in cases if not case["requires_browser"]]
    refused = {
        case["case_id"]: browser_refusal(case, "BROWSER_DISABLED")
        for case in browser_cases
    }
    false_refusals = [
        case["case_id"]
        for case in non_browser_cases
        if browser_refusal(case, "BROWSER_DISABLED") is not None
    ]
    if (
        len(browser_cases) != 8
        or any(value is None or not value["unsafe_fallback_refused"] for value in refused.values())
        or false_refusals
    ):
        raise QualificationError(
            f"browser hard-refusal routing mismatch: refused={refused}, false={false_refusals}"
        )
    normal_profile_candidates = [
        Path.home() / "Library" / "Application Support" / "Google" / "Chrome",
        Path.home() / "Library" / "Application Support" / "Firefox",
    ]
    # Deliberately inspect names only; never read or launch these profiles.
    named_only = [candidate.name for candidate in normal_profile_candidates]
    return (
        [
            {
                "contained_browser_candidates": [],
                "normal_profiles_read": False,
                "normal_profile_names_considered": named_only,
                "browser_cases_must_block": True,
                "browser_case_ids": sorted(refused),
                "all_browser_cases_refused": True,
                "non_browser_cases_refused": false_refusals,
            }
        ],
        "BROWSER_DISABLED",
    )


def qualify() -> tuple[dict[str, Any], Path]:
    run_id = f"cq-{int(time.time())}-{secrets.token_hex(6)}"
    run_root = ROOT / "work" / "temporary-state" / run_id
    run_root.mkdir(parents=True, mode=0o700)
    started = utc_now()
    checks: list[dict[str, Any]] = []
    browser_mode = "BROWSER_DISABLED"
    cleanup_verified = False
    try:
        digest = harness_digest()
        runtime = current_runtime(run_root)
        checks.append(check("CQ-001", lambda: cq_001(run_root / "cq001", run_id, secrets.token_hex(16))))
        checks.append(check("CQ-002", lambda: cq_002(run_root / "cq002", run_id, secrets.token_hex(16))))
        checks.append(check("CQ-003", lambda: cq_003(run_root / "cq003", run_id, IMAGE)))
        checks.append(
            check(
                "CQ-004",
                lambda: _watchdog_trial(run_root / "cq004", f"{run_id}-04", IMAGE, controller_death=True),
            )
        )
        checks.append(
            check(
                "CQ-005",
                lambda: _watchdog_trial(run_root / "cq005", f"{run_id}-05", IMAGE, controller_death=False),
            )
        )
        checks.append(
            check("CQ-006", lambda: cq_006(run_root / "cq006", f"{run_id}-06", IMAGE))
        )
        checks.append(check("CQ-007", cq_007))
        checks.append(check("CQ-008", lambda: cq_008(run_root / "cq008", f"{run_id}-08", IMAGE)))
        checks.append(check("CQ-009", lambda: cq_009(run_root / "cq009", f"{run_id}-09")))
        checks.append(check("CQ-010", lambda: cq_010(run_root / "cq010", digest, runtime)))
        checks.append(check("CQ-011", lambda: cq_011(run_root / "cq011", f"{run_id}-11", IMAGE)))
        try:
            observations, browser_mode = cq_012(run_root / "cq012", f"{run_id}-12", IMAGE)
            checks.append({"check_id": "CQ-012", "result": "PASS", "observations": redact(observations)})
        except Exception as exc:
            checks.append(
                {
                    "check_id": "CQ-012",
                    "result": "ERROR",
                    "observations": [{"error_type": type(exc).__name__, "detail": str(exc)}],
                }
            )
        try:
            cleanup_observation = verify_qualification_cleanup(run_id, run_root)
            shutil.rmtree(run_root)
            if run_root.exists():
                raise ProcessControlError("qualification temporary root remained after removal")
            cleanup_verified = True
            cq009 = next(item for item in checks if item["check_id"] == "CQ-009")
            cq009["observations"].append(
                {
                    "final_cleanup_verified_before_publication": True,
                    **cleanup_observation,
                    "temporary_root_absent": True,
                }
            )
        except Exception as exc:
            cq009 = next(item for item in checks if item["check_id"] == "CQ-009")
            cq009["result"] = "ERROR"
            cq009["observations"].append(
                {
                    "error_type": type(exc).__name__,
                    "detail": f"final cleanup verification failed: {exc}",
                }
            )
        result = aggregate_qualification_result(
            checks,
            cleanup_verified=cleanup_verified,
        )
        receipt = {
            "qualification_version": QUALIFICATION_VERSION,
            "run_id": run_id,
            "harness_digest": digest,
            "runtime": runtime,
            "started_at": started,
            "finished_at": utc_now(),
            "checks": checks,
            "browser_mode": browser_mode,
            "result": result,
            "limitations": [
                "The browser launcher is disabled unless CQ-012 records QUALIFIED.",
                "Qualification proves this exact harness and cached runtime identity only.",
            ],
        }
        validate_qualification_contract(receipt)
        run_path = ROOT / "results" / "runs" / run_id / "containment-qualification.json"
        latest_path = ROOT / "results" / "latest" / "containment-qualification.json"
        atomic_json(run_path, receipt)
        atomic_json(latest_path, receipt)
        return receipt, latest_path
    finally:
        if not cleanup_verified and run_root.exists():
            with contextlib.suppress(Exception):
                verify_qualification_cleanup(run_id, run_root)
            shutil.rmtree(run_root, ignore_errors=True)


def qualification_is_current(path: Path | None = None) -> tuple[bool, str]:
    target = path or ROOT / "results" / "latest" / "containment-qualification.json"
    if not target.exists():
        return False, "qualification receipt missing"
    try:
        receipt = load_json(target)
    except Exception as exc:
        return False, f"qualification receipt unreadable: {exc}"
    return qualification_receipt_is_current(receipt)


def qualification_receipt_is_current(receipt: dict[str, Any]) -> tuple[bool, str]:
    try:
        validate_qualification_contract(receipt)
    except Exception as exc:
        return False, f"qualification receipt invalid: {exc}"
    if receipt["result"] != "PASS":
        return False, f"qualification result is {receipt['result']}"
    if receipt["harness_digest"] != harness_digest():
        return False, "qualification harness digest is stale"
    runtime_root = ROOT / "work" / "temporary-state"
    runtime_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    try:
        if not receipt_runtime_is_current(receipt, runtime_root):
            return False, "qualification container image or runtime identity changed"
    except Exception as exc:
        return False, f"qualification runtime could not be rebound: {exc}"
    return True, receipt["browser_mode"]
