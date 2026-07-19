"""Trusted helper whose abrupt death is used to qualify the watchdog."""

from __future__ import annotations

import argparse
import json
import os
import signal
import sys
import time
from pathlib import Path

from harness.process_control import cleanup_labeled_containers, docker, safe_container_arguments


def atomic_json(path: Path, value: dict[str, object]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    temporary.write_text(json.dumps(value, sort_keys=True) + "\n", encoding="utf-8")
    os.replace(temporary, path)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-root", type=Path, required=True)
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--container-name", required=True)
    parser.add_argument("--image", required=True)
    parser.add_argument("--identity", type=Path, required=True)
    parser.add_argument("--lease", type=Path, required=True)
    parser.add_argument("--fixture", type=Path, required=True)
    args = parser.parse_args()

    args.run_root.mkdir(parents=True, exist_ok=True)
    canary = args.run_root / "container-canary"
    canary.mkdir(mode=0o777)
    os.chmod(canary, 0o777)
    code = args.fixture.read_text(encoding="utf-8")
    atomic_json(args.lease, {"run_id": args.run_id, "heartbeat_monotonic": time.monotonic()})
    launched = docker(
        safe_container_arguments(
            name=args.container_name,
            run_id=args.run_id,
            image=args.image,
            command=["node", "-e", code],
            canary_mount=canary,
            detached=True,
        ),
        cwd=args.run_root,
        timeout_seconds=20,
    )
    if launched.returncode != 0:
        sys.stderr.buffer.write(launched.stderr)
        return 2
    container_id = launched.stdout.decode().strip()
    atomic_json(
        args.identity,
        {
            "container_id": container_id,
            "container_name": args.container_name,
            "run_id": args.run_id,
        },
    )

    stopping = False

    def stop(_signum: int, _frame: object) -> None:
        nonlocal stopping
        stopping = True

    signal.signal(signal.SIGTERM, stop)
    signal.signal(signal.SIGINT, stop)
    try:
        while not stopping:
            atomic_json(
                args.lease,
                {"run_id": args.run_id, "heartbeat_monotonic": time.monotonic()},
            )
            time.sleep(0.05)
    finally:
        cleanup_labeled_containers(args.run_id, args.run_root)
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
