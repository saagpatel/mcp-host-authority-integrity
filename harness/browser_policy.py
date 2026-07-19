"""One hard browser routing decision shared by qualification and execution."""

from __future__ import annotations

from typing import Any


def browser_refusal(case: dict[str, Any], browser_mode: str) -> dict[str, Any] | None:
    if case["requires_browser"] and browser_mode != "QUALIFIED":
        return {
            "target_verdict": "BLOCKED",
            "blocked_kind": "ACCESS",
            "blocked_detail": (
                "CQ-012 is BROWSER_DISABLED; no current disposable launcher "
                "satisfied the full repeatable containment contract"
            ),
            "browser_required": True,
            "unsafe_fallback_refused": True,
        }
    return None
