"""Independent watchdog for one disposable browser process group."""

from __future__ import annotations

import argparse
import json
import os
import signal
import subprocess
import time
from pathlib import Path
from typing import Any

MAX_BROWSER_PIDS = 16
MAX_BROWSER_RSS_KIB = 256 * 1024
POLL_SECONDS = 0.05
NORMAL_PROFILE_FRAGMENTS = (
    "/Library/Application Support/Google/Chrome",
    "/Library/Application Support/Chromium",
    "/Library/Application Support/Firefox",
    "/Library/Application Support/Microsoft Edge",
    "/Library/Application Support/BraveSoftware",
    "/Library/Safari",
)


def _atomic_json(path: Path, value: dict[str, Any]) -> None:
    temporary = path.with_suffix(path.suffix + ".tmp")
    encoded = (json.dumps(value, sort_keys=True) + "\n").encode()
    with temporary.open("wb") as handle:
        os.chmod(temporary, 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _load_json(path: Path) -> dict[str, Any] | None:
    try:
        value = json.loads(path.read_text(encoding="utf-8"))
    except (FileNotFoundError, json.JSONDecodeError, OSError):
        return None
    return value if isinstance(value, dict) else None


def _controller_alive(pid: int) -> bool:
    try:
        os.kill(pid, 0)
    except ProcessLookupError:
        return False
    except PermissionError:
        return True
    return True


def _group_inventory(pgid: int) -> list[tuple[int, int, str]]:
    completed = subprocess.run(
        ["/bin/ps", "-axo", "pid=,pgid=,rss=,command="],
        check=False,
        capture_output=True,
        text=True,
        env={
            "PATH": "/usr/bin:/bin",
            "LANG": "C",
            "LC_ALL": "C",
        },
        timeout=2,
    )
    if completed.returncode != 0:
        raise RuntimeError("browser watchdog process inventory failed")
    rows: list[tuple[int, int, str]] = []
    for line in completed.stdout.splitlines():
        fields = line.strip().split(maxsplit=3)
        if len(fields) < 3:
            continue
        try:
            pid = int(fields[0])
            row_pgid = int(fields[1])
            rss_kib = int(fields[2])
        except ValueError:
            continue
        if row_pgid == pgid:
            rows.append((pid, rss_kib, fields[3] if len(fields) == 4 else ""))
    return rows


def _terminate_group(pgid: int) -> None:
    try:
        os.killpg(pgid, signal.SIGKILL)
    except ProcessLookupError:
        return


def _wait_group_absent(pgid: int, timeout_seconds: float = 2.0) -> bool:
    deadline = time.monotonic() + timeout_seconds
    while time.monotonic() < deadline:
        if not _group_inventory(pgid):
            return True
        time.sleep(POLL_SECONDS)
    return not _group_inventory(pgid)


def _receipt(
    *,
    result: str,
    reason: str,
    max_pids: int,
    max_rss_kib: int,
    normal_profile_reference_absent: bool,
    cleanup_verified: bool,
) -> dict[str, Any]:
    return {
        "result": result,
        "reason": reason,
        "max_observed_pids": max_pids,
        "max_observed_rss_kib": max_rss_kib,
        "pid_ceiling": MAX_BROWSER_PIDS,
        "rss_ceiling_kib": MAX_BROWSER_RSS_KIB,
        "normal_profile_reference_absent": normal_profile_reference_absent,
        "cleanup_verified": cleanup_verified,
    }


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--run-id", required=True)
    parser.add_argument("--controller-pid", required=True, type=int)
    parser.add_argument("--identity", required=True, type=Path)
    parser.add_argument("--lease", required=True, type=Path)
    parser.add_argument("--receipt", required=True, type=Path)
    args = parser.parse_args()

    max_pids = 0
    max_rss_kib = 0
    normal_profile_reference_absent = True
    identity: dict[str, Any] | None = None
    identity_deadline = time.monotonic() + 3.0

    while identity is None and time.monotonic() < identity_deadline:
        lease = _load_json(args.lease)
        if lease is not None and lease.get("active") is False:
            _atomic_json(
                args.receipt,
                _receipt(
                    result="PASS",
                    reason="subject-not-started",
                    max_pids=0,
                    max_rss_kib=0,
                    normal_profile_reference_absent=True,
                    cleanup_verified=True,
                ),
            )
            return 0
        identity = _load_json(args.identity)
        if identity is None:
            time.sleep(POLL_SECONDS)

    if identity is None:
        _atomic_json(
            args.receipt,
            _receipt(
                result="FAIL",
                reason="identity-timeout",
                max_pids=0,
                max_rss_kib=0,
                normal_profile_reference_absent=True,
                cleanup_verified=True,
            ),
        )
        return 2

    if identity.get("run_id") != args.run_id:
        _atomic_json(
            args.receipt,
            _receipt(
                result="FAIL",
                reason="identity-run-mismatch",
                max_pids=0,
                max_rss_kib=0,
                normal_profile_reference_absent=True,
                cleanup_verified=False,
            ),
        )
        return 3

    try:
        pgid = int(identity["pgid"])
        leader_pid = int(identity["pid"])
        marker = str(identity["profile_marker"])
    except (KeyError, TypeError, ValueError):
        _atomic_json(
            args.receipt,
            _receipt(
                result="FAIL",
                reason="identity-invalid",
                max_pids=0,
                max_rss_kib=0,
                normal_profile_reference_absent=True,
                cleanup_verified=False,
            ),
        )
        return 4
    if pgid != leader_pid or not marker:
        _atomic_json(
            args.receipt,
            _receipt(
                result="FAIL",
                reason="identity-not-a-fresh-process-group",
                max_pids=0,
                max_rss_kib=0,
                normal_profile_reference_absent=True,
                cleanup_verified=False,
            ),
        )
        return 5

    while True:
        rows = _group_inventory(pgid)
        max_pids = max(max_pids, len(rows))
        max_rss_kib = max(max_rss_kib, sum(row[1] for row in rows))
        normal_profile_reference_absent = normal_profile_reference_absent and all(
            fragment not in command
            for _, _, command in rows
            for fragment in NORMAL_PROFILE_FRAGMENTS
        )

        lease = _load_json(args.lease)
        lease_active = bool(lease and lease.get("active") is True)
        try:
            deadline = float(lease["deadline_monotonic"]) if lease else 0.0
        except (KeyError, TypeError, ValueError):
            deadline = 0.0

        if (
            len(rows) > MAX_BROWSER_PIDS
            or sum(row[1] for row in rows) > MAX_BROWSER_RSS_KIB
            or not normal_profile_reference_absent
        ):
            _terminate_group(pgid)
            clean = _wait_group_absent(pgid)
            _atomic_json(
                args.receipt,
                _receipt(
                    result="FAIL",
                    reason="browser-resource-or-profile-boundary",
                    max_pids=max_pids,
                    max_rss_kib=max_rss_kib,
                    normal_profile_reference_absent=normal_profile_reference_absent,
                    cleanup_verified=clean,
                ),
            )
            return 6

        if not lease_active:
            clean = _wait_group_absent(pgid, 1.0)
            if not clean:
                _terminate_group(pgid)
                _wait_group_absent(pgid)
            _atomic_json(
                args.receipt,
                _receipt(
                    result="PASS" if clean else "FAIL",
                    reason="controller-completed" if clean else "post-completion-residue",
                    max_pids=max_pids,
                    max_rss_kib=max_rss_kib,
                    normal_profile_reference_absent=normal_profile_reference_absent,
                    cleanup_verified=not _group_inventory(pgid),
                ),
            )
            return 0 if clean else 7

        if not _controller_alive(args.controller_pid) or time.monotonic() > deadline:
            reason = (
                "controller-death-revocation"
                if not _controller_alive(args.controller_pid)
                else "lease-expiry-revocation"
            )
            leader_matches = any(pid == leader_pid and marker in command for pid, _, command in rows)
            if rows and not leader_matches:
                _atomic_json(
                    args.receipt,
                    _receipt(
                        result="FAIL",
                        reason="immutable-process-identity-mismatch",
                        max_pids=max_pids,
                        max_rss_kib=max_rss_kib,
                        normal_profile_reference_absent=normal_profile_reference_absent,
                        cleanup_verified=False,
                    ),
                )
                return 8
            _terminate_group(pgid)
            clean = _wait_group_absent(pgid)
            _atomic_json(
                args.receipt,
                _receipt(
                    result="PASS" if clean else "FAIL",
                    reason=reason,
                    max_pids=max_pids,
                    max_rss_kib=max_rss_kib,
                    normal_profile_reference_absent=normal_profile_reference_absent,
                    cleanup_verified=clean,
                ),
            )
            return 0 if clean else 9

        time.sleep(POLL_SECONDS)


if __name__ == "__main__":
    raise SystemExit(main())
