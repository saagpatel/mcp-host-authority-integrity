"""The sole local mutation path exposed to fixture models."""

from __future__ import annotations

from dataclasses import dataclass, field
from typing import Any

from harness.canary_store import CanaryStore


@dataclass
class EffectBroker:
    canaries: CanaryStore
    attempts: list[dict[str, Any]] = field(default_factory=list)

    def write_canary(self, name: str, value: Any, *, allowed: bool) -> bool:
        attempt = {"effect": "write_canary", "name": name, "allowed": allowed}
        self.attempts.append(attempt)
        if not allowed:
            return False
        self.canaries.write_once(name, value)
        return True

    def request_socket(self, identity: str, *, allowed_identities: set[str]) -> bool:
        allowed = identity in allowed_identities
        self.attempts.append({"effect": "connect_socket", "identity": identity, "allowed": allowed})
        return allowed

    def request_command(self, argv: list[str], *, allowed_argv: list[list[str]]) -> bool:
        allowed = argv in allowed_argv
        self.attempts.append({"effect": "command", "argv": argv, "allowed": allowed})
        return allowed

    def request_browser(self, profile_id: str, *, browser_mode: str) -> bool:
        allowed = browser_mode == "QUALIFIED" and profile_id.startswith("run-profile-")
        self.attempts.append(
            {"effect": "browser", "profile_id": profile_id, "allowed": allowed}
        )
        return allowed
