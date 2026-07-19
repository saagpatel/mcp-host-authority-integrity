"""Program-owned canaries with path, link, identity, and digest checks."""

from __future__ import annotations

import hashlib
import json
import os
import stat
from pathlib import Path
from typing import Any


class CanaryError(RuntimeError):
    """A canary path or record violated the safety contract."""


def _canonical(value: Any) -> bytes:
    return json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True).encode()


class CanaryStore:
    def __init__(self, root: Path, run_id: str, nonce: str) -> None:
        self.root = root.resolve()
        self.run_id = run_id
        self.nonce = nonce
        self.root.mkdir(parents=True, exist_ok=True, mode=0o700)
        if self.root.is_symlink() or not self.root.is_dir():
            raise CanaryError("canary root must be a real directory")
        flags = os.O_RDONLY
        if hasattr(os, "O_DIRECTORY"):
            flags |= os.O_DIRECTORY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        self._root_descriptor = os.open(self.root, flags)
        root_stat = os.fstat(self._root_descriptor)
        self._root_identity = (root_stat.st_dev, root_stat.st_ino)

    def close(self) -> None:
        descriptor = getattr(self, "_root_descriptor", -1)
        if descriptor >= 0:
            os.close(descriptor)
            self._root_descriptor = -1

    def __enter__(self) -> "CanaryStore":
        return self

    def __exit__(self, *_args: object) -> None:
        self.close()

    def __del__(self) -> None:
        try:
            self.close()
        except OSError:
            pass

    def _validate_name(self, name: str) -> None:
        if not name or name in {".", ".."} or "/" in name or "\0" in name:
            raise CanaryError("canary name must be one plain path component")

    def _verify_root_binding(self) -> None:
        try:
            current = os.stat(self.root, follow_symlinks=False)
        except FileNotFoundError as exc:
            raise CanaryError("canary root pathname disappeared") from exc
        if not stat.S_ISDIR(current.st_mode) or (current.st_dev, current.st_ino) != self._root_identity:
            raise CanaryError("canary root pathname no longer names the pinned directory")

    def _open_relative(self, name: str, flags: int, mode: int | None = None) -> int:
        if mode is None:
            return os.open(name, flags, dir_fd=self._root_descriptor)
        return os.open(name, flags, mode, dir_fd=self._root_descriptor)

    def path_for(self, name: str) -> Path:
        self._validate_name(name)
        self._verify_root_binding()
        path = self.root / name
        return path

    def write_once(self, name: str, value: Any) -> dict[str, Any]:
        self._validate_name(name)
        self._verify_root_binding()
        record = {"run_id": self.run_id, "nonce": self.nonce, "value": value}
        record["digest"] = hashlib.sha256(_canonical(record)).hexdigest()
        data = _canonical(record) + b"\n"
        flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = self._open_relative(name, flags, 0o600)
        try:
            try:
                self._verify_root_binding()
            except CanaryError:
                os.unlink(name, dir_fd=self._root_descriptor)
                raise
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CanaryError("canary target is not a singly linked regular file")
            os.write(descriptor, data)
            os.fsync(descriptor)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino) != (after.st_dev, after.st_ino):
                raise CanaryError("canary identity changed during write")
        finally:
            os.close(descriptor)
        return self.read(name)

    def read(self, name: str) -> dict[str, Any]:
        self._validate_name(name)
        self._verify_root_binding()
        flags = os.O_RDONLY
        if hasattr(os, "O_NOFOLLOW"):
            flags |= os.O_NOFOLLOW
        descriptor = self._open_relative(name, flags)
        try:
            self._verify_root_binding()
            before = os.fstat(descriptor)
            if not stat.S_ISREG(before.st_mode) or before.st_nlink != 1:
                raise CanaryError("canary is not a singly linked regular file")
            if before.st_size > 64 * 1024:
                raise CanaryError("canary exceeds its size ceiling")
            data = os.read(descriptor, 64 * 1024 + 1)
            after = os.fstat(descriptor)
            if (before.st_dev, before.st_ino, before.st_size) != (
                after.st_dev,
                after.st_ino,
                after.st_size,
            ):
                raise CanaryError("canary changed during read")
        finally:
            os.close(descriptor)
        record = json.loads(data)
        digest = record.pop("digest", None)
        if record.get("run_id") != self.run_id or record.get("nonce") != self.nonce:
            raise CanaryError("canary identity does not match the current run")
        if digest != hashlib.sha256(_canonical(record)).hexdigest():
            raise CanaryError("canary digest mismatch")
        record["digest"] = digest
        return record

    def absent(self, name: str) -> bool:
        self._validate_name(name)
        self._verify_root_binding()
        try:
            os.stat(name, dir_fd=self._root_descriptor, follow_symlinks=False)
        except FileNotFoundError:
            return True
        return False
