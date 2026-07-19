"""Atomic duplicate-execution and replay rejection."""

from __future__ import annotations

import json
import os
from pathlib import Path


class DuplicateExecutionError(RuntimeError):
    """The run/case or result identity already exists."""


class ExecutionLedger:
    def __init__(self, root: Path) -> None:
        self.root = root.resolve()
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)

    def claim(self, run_id: str, case_id: str) -> Path:
        if not run_id or "/" in run_id or not case_id or "/" in case_id:
            raise ValueError("ledger identities must be plain path components")
        path = self.root / f"{run_id}--{case_id}.claim"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        try:
            descriptor = os.open(path, flags, 0o600)
        except FileExistsError as exc:
            raise DuplicateExecutionError(f"duplicate execution: {run_id}/{case_id}") from exc
        try:
            os.write(
                descriptor,
                (json.dumps({"run_id": run_id, "case_id": case_id}, sort_keys=True) + "\n").encode(),
            )
            os.fsync(descriptor)
        finally:
            os.close(descriptor)
        return path


def write_once(path: Path, data: bytes) -> None:
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    try:
        descriptor = os.open(path, flags, 0o600)
    except FileExistsError as exc:
        raise DuplicateExecutionError(f"result replay refused: {path.name}") from exc
    try:
        os.write(descriptor, data)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
