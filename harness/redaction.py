"""Fail-closed evidence redaction and size/depth enforcement."""

from __future__ import annotations

import json
import re
import base64
from urllib.parse import unquote
from typing import Any

MAX_EVIDENCE_BYTES = 256 * 1024
MAX_DEPTH = 32
REDACTED = "[REDACTED_SYNTHETIC_SECRET]"

SENSITIVE_KEY = re.compile(
    r"(authorization|cookie|password|passwd|secret|token|private.?key|credential|session)",
    re.IGNORECASE,
)
SENSITIVE_VALUE = re.compile(
    r"(Bearer\s+[A-Za-z0-9._~+/-]{8,}|"
    r"-----BEGIN [A-Z ]*PRIVATE KEY-----|"
    r"(?:token|secret|cookie|password)[:=][^\s,;]{4,})",
    re.IGNORECASE,
)
HOME_PATH = re.compile(r"/Users/[^/\s]+|/home/[^/\s]+")
BASE64_VALUE = re.compile(r"(?<![A-Za-z0-9+/])([A-Za-z0-9+/_-]{16,}={0,2})(?![A-Za-z0-9+/])")
CONTROL_CHAR = re.compile(r"[\x00-\x08\x0b\x0c\x0e-\x1f\x7f]")


class RedactionError(RuntimeError):
    """Evidence could not be made safe to persist."""


def _redact(value: Any, depth: int) -> Any:
    if depth > MAX_DEPTH:
        raise RedactionError("evidence nesting exceeds maximum depth")
    if value is None or isinstance(value, (bool, int, float)):
        return value
    if isinstance(value, bytes):
        try:
            value = value.decode("utf-8", errors="strict")
        except UnicodeDecodeError as exc:
            raise RedactionError("invalid UTF-8 evidence") from exc
    if isinstance(value, str):
        decoded = unquote(value)
        if decoded != value and SENSITIVE_VALUE.search(decoded):
            return REDACTED
        for candidate in BASE64_VALUE.findall(value):
            padded = candidate + "=" * (-len(candidate) % 4)
            try:
                raw = base64.urlsafe_b64decode(padded).decode("utf-8", errors="strict")
            except (ValueError, UnicodeDecodeError):
                continue
            if SENSITIVE_VALUE.search(raw) or re.search(
                r"(TOKEN|SECRET|COOKIE|PASSWORD|PRIVATE.?KEY)", raw, re.IGNORECASE
            ):
                return REDACTED
        without_controls = CONTROL_CHAR.sub("[CONTROL]", value)
        return HOME_PATH.sub("/<HOME>", SENSITIVE_VALUE.sub(REDACTED, without_controls))
    if isinstance(value, list):
        return [_redact(item, depth + 1) for item in value]
    if isinstance(value, dict):
        clean: dict[str, Any] = {}
        for key, item in value.items():
            if not isinstance(key, str):
                raise RedactionError("evidence object keys must be strings")
            clean[key] = REDACTED if SENSITIVE_KEY.search(key) else _redact(item, depth + 1)
        return clean
    raise RedactionError(f"unsupported evidence type: {type(value).__name__}")


def redact(value: Any) -> Any:
    clean = _redact(value, 0)
    encoded = json.dumps(clean, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    if len(encoded.encode("utf-8")) > MAX_EVIDENCE_BYTES:
        raise RedactionError("redacted evidence exceeds maximum size")
    if SENSITIVE_VALUE.search(encoded):
        raise RedactionError("sensitive pattern remained after redaction")
    return clean
