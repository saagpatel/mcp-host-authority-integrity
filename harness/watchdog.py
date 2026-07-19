"""Independent lease watchdog for a disposable container identity."""

from __future__ import annotations

import argparse
import json
import os
import time
from collections.abc import Callable
from pathlib import Path

from harness.process_control import (
    Completed,
    ProcessControlError,
    cleanup_labeled_containers,
    docker,
)


def atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def revoke_container(
    container_id: str,
    run_id: str,
    run_root: Path,
    *,
    docker_call: Callable[..., Completed] = docker,
) -> list[str]:
    killed = docker_call(["kill", container_id], cwd=run_root)
    if killed.returncode != 0:
        raise ProcessControlError(
            f"container kill failed for {container_id}: "
            f"{killed.stderr.decode(errors='replace')}"
        )
    return cleanup_labeled_containers(
        run_id,
        run_root,
        docker_call=docker_call,
    )


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--receipt", type=Path, required=True)
    parser.add_argument("--identity-wait", type=float, default=10.0)
    parser.add_argument("--heartbeat-grace", type=float, default=0.30)
    args = parser.parse_args()

    deadline = time.monotonic() + args.identity_wait
    while not args.identity.exists() and time.monotonic() < deadline:
        time.sleep(0.05)
    if not args.identity.exists():
        atomic_json(args.receipt, {"result": "FAIL", "reason": "identity-timeout"})
        return 2
    identity = json.loads(args.identity.read_text(encoding="utf-8"))
    if identity.get("run_id") != args.run_id:
        atomic_json(args.receipt, {"result": "FAIL", "reason": "identity-run-mismatch"})
        return 3

    while True:
        try:
            lease = json.loads(args.lease.read_text(encoding="utf-8"))
            heartbeat = float(lease["heartbeat_monotonic"])
            if lease.get("run_id") != args.run_id:
                break
            if time.monotonic() - heartbeat > args.heartbeat_grace:
                break
        except (FileNotFoundError, KeyError, TypeError, ValueError, json.JSONDecodeError):
            break
        time.sleep(0.05)

    container_id = str(identity["container_id"])
    inspected = docker(
        ["inspect", "--format", "{{ index .Config.Labels \"mhai.run_id\" }}", container_id],
        cwd=args.run_root,
    )
    actual_label = inspected.stdout.decode().strip()
    if inspected.returncode != 0 or actual_label != args.run_id:
        atomic_json(
            args.receipt,
            {
                "result": "FAIL",
                "reason": "immutable-identity-verification",
                "container_id": container_id,
                "actual_label": actual_label,
                "inspect_returncode": inspected.returncode,
                "inspect_stderr": inspected.stderr.decode(errors="replace"),
            },
        )
        return 4
    try:
        removed = revoke_container(container_id, args.run_id, args.run_root)
    except ProcessControlError as exc:
        atomic_json(
            args.receipt,
            {
                "result": "FAIL",
                "reason": "lease-revocation-cleanup",
                "container_id": container_id,
                "run_id": args.run_id,
                "detail": str(exc),
            },
        )
        return 5
    atomic_json(
        args.receipt,
        {
            "result": "PASS",
            "reason": "lease-revoked",
            "container_id": container_id,
            "run_id": args.run_id,
            "removed_after_kill": removed,
            "remaining": [],
        },
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
