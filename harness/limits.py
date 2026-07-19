"""Exact protocol and evidence resource ceilings."""

from __future__ import annotations

from typing import Any


class LimitExceeded(ValueError):
    """Input exceeded a declared resource ceiling."""


REQUEST_BYTES = 1 * 1024 * 1024
RESPONSE_BYTES = 2 * 1024 * 1024
DECOMPRESSED_BYTES = 4 * 1024 * 1024
REDIRECTS = 5
SCHEMA_DEPTH = 64


def enforce_bytes(value: bytes, limit: int, label: str) -> bytes:
    if len(value) > limit:
        raise LimitExceeded(f"{label} exceeds {limit} bytes")
    return value


def enforce_redirects(count: int) -> int:
    if count > REDIRECTS:
        raise LimitExceeded(f"redirect count exceeds {REDIRECTS}")
    return count


def depth_of(value: Any, current: int = 0) -> int:
    if current > SCHEMA_DEPTH:
        raise LimitExceeded(f"schema depth exceeds {SCHEMA_DEPTH}")
    if isinstance(value, dict):
        return max([current, *(depth_of(item, current + 1) for item in value.values())])
    if isinstance(value, list):
        return max([current, *(depth_of(item, current + 1) for item in value)])
    return current


def enforce_schema_depth(value: Any) -> Any:
    depth_of(value)
    return value
