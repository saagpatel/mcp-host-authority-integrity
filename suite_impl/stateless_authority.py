"""Deterministic in-memory oracles for the Stateless Authority suite.

The fixture-backed cases deliberately run two fresh control domains:

* a vulnerable positive control that must demonstrate the catalog fail oracle;
* a safe negative control that must demonstrate the catalog pass oracle.

The official-SDK cases are different. SA-014 fails closed without the exact Go
SDK. SA-015 executes exact cached Python and TypeScript SDK request parsers in
the qualified no-network container and never substitutes lookalike behavior.
"""

from __future__ import annotations

import json
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any
from urllib.parse import unquote

from harness.execution import Evaluation, RunContext
from harness.process_control import (
    cleanup_labeled_containers,
    docker,
    safe_container_arguments,
)
from harness.qualification import IMAGE


@dataclass(frozen=True)
class _Contract:
    status: str
    pass_oracle: str
    fail_oracle: str
    evidence_basis: str


_CONTRACTS: dict[str, _Contract] = {
    "SA-001": _Contract(
        "FINAL_PROPOSAL",
        "Cross-principal, cross-tool, neighboring, expired, and revoked handles are rejected without disclosure.",
        "Possession of any tested invalid-authority handle grants continuation or data.",
        "SEP-2567 is a final proposal; this result is fixture evidence, not released-core conformance.",
    ),
    "SA-002": _Contract(
        "FINAL_PROPOSAL",
        "Every byte, field, encoding, casing, and wrapper mutation is rejected.",
        "Any tampered handle is normalized into a valid authorization context.",
        "SEP-2567 is a final proposal; tamper rejection is the fixture's explicit security contract.",
    ),
    "SA-003": _Contract(
        "FINAL_PROPOSAL",
        "Every cross-user, cross-tool, cross-prompt, and cross-request swap is rejected.",
        "Swapped continuation material resumes or performs an unauthorized effect.",
        "Continuation binding is evaluated as a final-proposal fixture invariant.",
    ),
    "SA-004": _Contract(
        "FINAL_PROPOSAL",
        "Retries return one stable outcome while the canary counter remains exactly one.",
        "The downstream canary counter exceeds one.",
        "Idempotent continuation is evaluated as a final-proposal fixture invariant.",
    ),
    "SA-005": _Contract(
        "RELEASED_EXPERIMENTAL",
        "Principal B receives indistinguishable denial for every operation on A's task.",
        "B observes task details or changes A's task.",
        "MCP Tasks shipped in 2025-11-25 but remain explicitly experimental.",
    ),
    "SA-006": _Contract(
        "RELEASED_EXPERIMENTAL",
        "Revoked principal A cannot retrieve delayed results or complete a pending side effect.",
        "Previously held authority remains sufficient after revocation.",
        "Current-authority rechecking is a fixture strengthening of released-experimental Tasks.",
    ),
    "SA-007": _Contract(
        "RELEASED_EXPERIMENTAL",
        "All race schedules reconcile to stopped or completed truth and no post-cancel canary appears.",
        "The client reports cancellation while work continues or the boundary is crossed later.",
        "MCP cancellation is cooperative; cessation truth is an explicit fixture safety invariant.",
    ),
    "SA-008": _Contract(
        "RELEASED_EXPERIMENTAL",
        "A request omitting Tasks is handled synchronously or rejected without task creation.",
        "Stale capability state causes an unadvertised task response.",
        "Capability negotiation is released-experimental Tasks behavior.",
    ),
    "SA-009": _Contract(
        "FINAL_PROPOSAL",
        "Requests without a parent, after completion, or with a forged parent are rejected without releasing data.",
        "Any forged or stale association releases model, user, or filesystem-shaped synthetic data.",
        "Parent association is SEP-2260 final-proposal behavior, not 2025-11-25 released core.",
    ),
    "SA-010": _Contract(
        "FINAL_PROPOSAL",
        "Duplicate Mcp-Method/Mcp-Name fields, case-varied header names, invalid encodings, proxy normalization, and any header/body value disagreement are rejected before authorization.",
        "Any disagreement selects one authority input and reaches the canary action.",
        "Header/body authority binding is SEP-2243 final-proposal behavior.",
    ),
    "SA-011": _Contract(
        "FIXTURE_SECURITY_INVARIANT",
        "Every boundary change causes a miss and only the exact original authority tuple hits.",
        "A private synthetic result crosses any changed authority dimension.",
        "MCP does not define this cache key; the oracle is fixture-only.",
    ),
    "SA-012": _Contract(
        "RELEASED_CORE",
        "A forged trusted-looking identity receives the same policy decision as an untrusted client.",
        "Self-asserted metadata changes an authorization outcome.",
        "Client implementation metadata is released-core data, not authenticated identity.",
    ),
    "SA-013": _Contract(
        "FIXTURE_SECURITY_INVARIANT",
        "Connection, handle, client, and tool-name rotation cannot reset the principal-operation budget.",
        "Rotation restores budget before the bounded window expires.",
        "MCP requires rate limiting but does not define the key; this oracle is fixture-only.",
    ),
    "SA-014": _Contract(
        "OFFICIAL_GUIDANCE",
        "The exact version and configuration reject every hostile request while accepting the valid control.",
        "Any hostile input reaches the handler or the version/configuration is not exact.",
        "OFFICIAL_SDK evidence requires an exact isolated Go SDK, not a simulated implementation.",
    ),
    "SA-015": _Contract(
        "OFFICIAL_GUIDANCE",
        "Duplicate keys, mixed case, confusables, unknown fields, and conflicts yield identical safe decisions.",
        "Available SDKs disagree in a way that can change authorization or execution.",
        "OFFICIAL_SDK evidence requires exact isolated SDK parsers, not Python lookalikes.",
    ),
}


def _case_contract_error(case: dict[str, Any], contract: _Contract) -> str | None:
    expected = {
        "protocol_status": contract.status,
        "pass_oracle": contract.pass_oracle,
        "fail_oracle": contract.fail_oracle,
        "requires_browser": False,
    }
    mismatches = [
        field
        for field, value in expected.items()
        if case.get(field) != value
    ]
    if mismatches:
        return "catalog contract mismatch: " + ", ".join(sorted(mismatches))
    return None


def _observation(
    case_id: str,
    contract: _Contract,
    positive_facts: dict[str, Any],
    negative_facts: dict[str, Any],
    positive_satisfied: bool,
    negative_satisfied: bool,
) -> dict[str, Any]:
    return {
        "case_id": case_id,
        "protocol_status": contract.status,
        "evidence_basis": contract.evidence_basis,
        "pass_oracle": contract.pass_oracle,
        "fail_oracle": contract.fail_oracle,
        "synthetic_only": True,
        "control_domains": {
            "positive": {
                "domain_id": f"{case_id.lower()}-positive",
                "deliberately_vulnerable": True,
                "fail_oracle_observed": positive_satisfied,
                "facts": positive_facts,
            },
            "negative": {
                "domain_id": f"{case_id.lower()}-negative",
                "safe_fixture": True,
                "pass_oracle_observed": negative_satisfied,
                "facts": negative_facts,
            },
        },
    }


def _handle_theft() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    denial = {"allowed": False, "code": "not_found"}
    records: dict[str, dict[str, Any]] = {
        "handle-live": {
            "principal": "principal-a",
            "tool": "tool-a",
            "expires": 20,
            "revoked": False,
            "data": "synthetic-canary",
        },
        "handle-expired": {
            "principal": "principal-a",
            "tool": "tool-a",
            "expires": 5,
            "revoked": False,
            "data": "synthetic-canary",
        },
        "handle-revoked": {
            "principal": "principal-a",
            "tool": "tool-a",
            "expires": 20,
            "revoked": True,
            "data": "synthetic-canary",
        },
    }

    def vulnerable(handle: str, principal: str, tool: str, now: int) -> dict[str, Any]:
        del principal, tool, now
        record = records.get(handle)
        if record is None:
            return denial
        return {"allowed": True, "data": record["data"]}

    def safe(handle: str, principal: str, tool: str, now: int) -> dict[str, Any]:
        record = records.get(handle)
        if (
            record is None
            or record["principal"] != principal
            or record["tool"] != tool
            or record["expires"] <= now
            or record["revoked"]
        ):
            return denial
        return {"allowed": True, "data": record["data"]}

    attacks = {
        "cross_principal": ("handle-live", "principal-b", "tool-a", 10),
        "cross_tool": ("handle-live", "principal-a", "tool-b", 10),
        "neighboring": ("handle-livf", "principal-a", "tool-a", 10),
        "expired": ("handle-expired", "principal-a", "tool-a", 10),
        "revoked": ("handle-revoked", "principal-a", "tool-a", 10),
    }
    vulnerable_results = {name: vulnerable(*args) for name, args in attacks.items()}
    safe_results = {name: safe(*args) for name, args in attacks.items()}
    positive = any(result.get("allowed") for result in vulnerable_results.values())
    negative = all(result == denial for result in safe_results.values())
    return (
        {
            "granted_variants": sorted(
                name for name, result in vulnerable_results.items() if result.get("allowed")
            ),
        },
        {
            "rejected_variants": sorted(
                name for name, result in safe_results.items() if result == denial
            ),
            "uniform_denial": len({json.dumps(value, sort_keys=True) for value in safe_results.values()}) == 1,
            "disclosure": False,
        },
        positive,
        negative,
    )


def _handle_tampering() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    valid = "v1:alpha:proof"
    mutations = {
        "byte": "v1:alphb:proof",
        "field": "v1:beta:proof",
        "encoding": "v1%3Aalpha%3Aproof",
        "casing": "V1:ALPHA:PROOF",
        "wrapper": '{"handle":"v1:alpha:proof"}',
    }

    def vulnerable(value: str) -> bool:
        candidate = value
        if value.startswith("{"):
            try:
                candidate = str(json.loads(value)["handle"])
            except (KeyError, TypeError, ValueError):
                return False
        return unquote(candidate).casefold() == valid.casefold()

    def safe(value: str) -> bool:
        return value == valid

    vulnerable_accepted = sorted(name for name, value in mutations.items() if vulnerable(value))
    safe_rejected = sorted(name for name, value in mutations.items() if not safe(value))
    return (
        {"normalized_into_authority": vulnerable_accepted},
        {"rejected_mutation_classes": safe_rejected, "valid_control_accepted": safe(valid)},
        bool(vulnerable_accepted),
        safe_rejected == sorted(mutations) and safe(valid),
    )


def _continuation_swap() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    expected = {
        "principal": "principal-a",
        "server": "server-a",
        "operation": "tool:write",
        "request": "request-a",
    }
    swaps = {
        "cross_user": {**expected, "principal": "principal-b"},
        "cross_server": {**expected, "server": "server-b"},
        "cross_tool": {**expected, "operation": "tool:read"},
        "cross_prompt": {**expected, "operation": "prompt:review"},
        "cross_request": {**expected, "request": "request-b"},
    }

    def vulnerable(candidate: dict[str, str]) -> bool:
        del candidate
        return True

    def safe(candidate: dict[str, str]) -> bool:
        return candidate == expected

    vulnerable_resumed = sorted(name for name, value in swaps.items() if vulnerable(value))
    safe_rejected = sorted(name for name, value in swaps.items() if not safe(value))
    return (
        {"unauthorized_effect_variants": vulnerable_resumed},
        {"rejected_swap_classes": safe_rejected, "originating_request_accepted": safe(expected)},
        bool(vulnerable_resumed),
        safe_rejected == sorted(swaps) and safe(expected),
    )


def _input_replay() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    class Fixture:
        def __init__(self, safe: bool) -> None:
            self.safe = safe
            self.counter = 0
            self.outcomes: dict[str, str] = {}

        def submit(self, key: str) -> str:
            if self.safe and key in self.outcomes:
                return self.outcomes[key]
            self.counter += 1
            outcome = "synthetic-outcome"
            self.outcomes[key] = outcome
            return outcome

    vulnerable = Fixture(safe=False)
    vulnerable_outcomes = [vulnerable.submit("input-key"), vulnerable.submit("input-key")]
    safe = Fixture(safe=True)
    safe_outcomes = [safe.submit("input-key"), safe.submit("input-key")]
    return (
        {"counter": vulnerable.counter, "stable_outcome": len(set(vulnerable_outcomes)) == 1},
        {"counter": safe.counter, "stable_outcome": len(set(safe_outcomes)) == 1},
        vulnerable.counter > 1,
        safe.counter == 1 and len(set(safe_outcomes)) == 1,
    )


def _task_cross_tenant() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    denial = {"ok": False, "code": "not_found"}
    operations = ("get", "update", "cancel", "list", "result")

    def vulnerable(operation: str) -> dict[str, Any]:
        return {
            "ok": True,
            "operation": operation,
            "details": "synthetic-task-a",
            "changed": operation in {"update", "cancel"},
        }

    def safe(operation: str) -> dict[str, Any]:
        del operation
        return denial

    vulnerable_results = {operation: vulnerable(operation) for operation in operations}
    safe_results = {operation: safe(operation) for operation in operations}
    return (
        {
            "b_observed": sorted(
                operation for operation, result in vulnerable_results.items() if result["ok"]
            ),
            "b_changed": sorted(
                operation for operation, result in vulnerable_results.items() if result["changed"]
            ),
        },
        {
            "denied_operations": sorted(
                operation for operation, result in safe_results.items() if result == denial
            ),
            "indistinguishable_denial": len(
                {json.dumps(value, sort_keys=True) for value in safe_results.values()}
            )
            == 1,
        },
        any(result["ok"] for result in vulnerable_results.values()),
        all(result == denial for result in safe_results.values()),
    )


def _task_revocation() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    class Fixture:
        def __init__(self, safe: bool) -> None:
            self.safe = safe
            self.authorized_at_creation = True
            self.currently_authorized = True
            self.side_effects = 0

        def revoke(self) -> None:
            self.currently_authorized = False

        def retrieve(self) -> bool:
            authorized = (
                self.currently_authorized if self.safe else self.authorized_at_creation
            )
            if authorized:
                self.side_effects += 1
                return True
            return False

    vulnerable = Fixture(safe=False)
    vulnerable.revoke()
    vulnerable_retrieved = vulnerable.retrieve()
    safe = Fixture(safe=True)
    safe.revoke()
    safe_retrieved = safe.retrieve()
    return (
        {
            "retrieved_after_revocation": vulnerable_retrieved,
            "pending_side_effects_completed": vulnerable.side_effects,
        },
        {
            "retrieved_after_revocation": safe_retrieved,
            "pending_side_effects_completed": safe.side_effects,
        },
        vulnerable_retrieved or vulnerable.side_effects > 0,
        not safe_retrieved and safe.side_effects == 0,
    )


def _cancellation_race() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    schedules = ("cancel_before_work", "cancel_at_boundary", "complete_before_cancel")

    def vulnerable(schedule: str) -> dict[str, Any]:
        if schedule == "complete_before_cancel":
            return {"truth": "completed", "reported": "completed", "post_cancel_canary": False}
        return {"truth": "running", "reported": "cancelled", "post_cancel_canary": True}

    def safe(schedule: str) -> dict[str, Any]:
        if schedule == "complete_before_cancel":
            return {"truth": "completed", "reported": "completed", "post_cancel_canary": False}
        return {"truth": "stopped", "reported": "cancelled", "post_cancel_canary": False}

    vulnerable_results = {schedule: vulnerable(schedule) for schedule in schedules}
    safe_results = {schedule: safe(schedule) for schedule in schedules}
    positive = any(
        result["reported"] == "cancelled"
        and (result["truth"] == "running" or result["post_cancel_canary"])
        for result in vulnerable_results.values()
    )
    negative = all(
        result["truth"] in {"stopped", "completed"} and not result["post_cancel_canary"]
        for result in safe_results.values()
    )
    return (
        {
            "misreported_schedules": sorted(
                schedule
                for schedule, result in vulnerable_results.items()
                if result["reported"] == "cancelled"
                and (result["truth"] == "running" or result["post_cancel_canary"])
            )
        },
        {
            "reconciled_schedules": sorted(safe_results),
            "post_cancel_canaries": sum(
                1 for result in safe_results.values() if result["post_cancel_canary"]
            ),
        },
        positive,
        negative,
    )


def _task_capability_stickiness() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    class Fixture:
        def __init__(self, safe: bool) -> None:
            self.safe = safe
            self.remembered_tasks = False
            self.created = 0

        def request(self, advertises_tasks: bool) -> str:
            effective = advertises_tasks if self.safe else (advertises_tasks or self.remembered_tasks)
            self.remembered_tasks = self.remembered_tasks or advertises_tasks
            if effective:
                self.created += 1
                return "task"
            return "synchronous"

    vulnerable = Fixture(safe=False)
    vulnerable_first = vulnerable.request(True)
    vulnerable_second = vulnerable.request(False)
    safe = Fixture(safe=True)
    safe_first = safe.request(True)
    safe_second = safe.request(False)
    return (
        {
            "first_response": vulnerable_first,
            "omitting_request_response": vulnerable_second,
            "task_count": vulnerable.created,
        },
        {
            "first_response": safe_first,
            "omitting_request_response": safe_second,
            "task_count": safe.created,
            "unadvertised_task_created": safe_second == "task",
        },
        vulnerable_second == "task",
        safe_second in {"synchronous", "rejected"} and safe.created == 1,
    )


def _parent_request_binding() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    attacks = {
        "sampling_without_parent": ("sampling", None),
        "elicitation_after_completion": ("elicitation", "parent-completed"),
        "roots_forged_parent": ("roots", "parent-forged"),
    }
    live_parent = "parent-live"
    completed = {"parent-completed"}

    def vulnerable(kind: str, parent: str | None) -> bool:
        del kind
        return parent is not None

    def safe(kind: str, parent: str | None) -> bool:
        del kind
        return parent == live_parent and parent not in completed

    vulnerable_releases = sorted(
        name for name, args in attacks.items() if vulnerable(*args)
    )
    safe_releases = sorted(name for name, args in attacks.items() if safe(*args))
    return (
        {"released_shapes": vulnerable_releases},
        {
            "rejected_associations": sorted(set(attacks) - set(safe_releases)),
            "released_shapes": safe_releases,
            "live_parent_control_accepted": safe("sampling", live_parent),
        },
        bool(vulnerable_releases),
        not safe_releases and safe("sampling", live_parent),
    )


def _header_body_binding() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    body: dict[str, Any] = {
        "method": "tools/call",
        "params": {"name": "synthetic.write"},
    }
    valid_headers = [
        ("Mcp-Method", "tools/call"),
        ("Mcp-Name", "synthetic.write"),
    ]
    attacks: dict[str, list[tuple[str, str]]] = {
        "duplicate_method": [
            ("Mcp-Method", "tools/call"),
            ("Mcp-Method", "resources/read"),
            ("Mcp-Name", "synthetic.write"),
        ],
        "case_varied_duplicate_name": [
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "synthetic.write"),
            ("mCP-nAME", "synthetic.read"),
        ],
        "invalid_encoding": [
            ("Mcp-\udcff", "tools/call"),
            ("Mcp-Name", "synthetic.write"),
        ],
        "proxy_normalization": [
            ("Mcp-Method", "tools%2Fcall"),
            ("Mcp-Name", "synthetic.write"),
        ],
        "method_disagreement": [
            ("Mcp-Method", "resources/read"),
            ("Mcp-Name", "synthetic.write"),
        ],
        "name_disagreement": [
            ("Mcp-Method", "tools/call"),
            ("Mcp-Name", "synthetic.read"),
        ],
    }

    def vulnerable(headers: list[tuple[str, str]]) -> bool:
        del headers
        return body["method"] == "tools/call"

    def safe(headers: list[tuple[str, str]]) -> bool:
        parsed: dict[str, list[str]] = {}
        for name, value in headers:
            try:
                name.encode("ascii")
                value.encode("ascii")
            except UnicodeEncodeError:
                return False
            parsed.setdefault(name.casefold(), []).append(value)
        methods = parsed.get("mcp-method", [])
        names = parsed.get("mcp-name", [])
        if len(methods) != 1 or len(names) != 1:
            return False
        return (
            methods[0] == body["method"]
            and names[0] == body["params"]["name"]
        )

    vulnerable_actions = sorted(
        name for name, headers in attacks.items() if vulnerable(headers)
    )
    safe_rejected = sorted(name for name, headers in attacks.items() if not safe(headers))
    return (
        {"disagreements_reaching_canary": vulnerable_actions},
        {
            "rejected_before_authorization": safe_rejected,
            "valid_control_reached_canary": safe(valid_headers),
        },
        bool(vulnerable_actions),
        safe_rejected == sorted(attacks) and safe(valid_headers),
    )


def _cache_isolation() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    original = {
        "user": "user-a",
        "scope": "private:read",
        "server": "server-a",
        "authorization": "active-a",
        "expiry": 100,
        "operation": "read-private",
    }
    changes = {
        "user": {**original, "user": "user-b"},
        "scope": {**original, "scope": "public:read"},
        "server": {**original, "server": "server-b"},
        "authorization": {**original, "authorization": "revoked-a"},
        "expiry": {**original, "expiry": 101},
    }
    private_result = "synthetic-private-result"

    def safe_key(authority: dict[str, Any]) -> tuple[Any, ...]:
        return (
            authority["user"],
            authority["scope"],
            authority["server"],
            authority["authorization"],
            authority["expiry"],
            authority["operation"],
        )

    vulnerable_cache = {original["operation"]: private_result}
    safe_cache = {safe_key(original): private_result}

    def safe_get(authority: dict[str, Any], now: int) -> str | None:
        if authority["expiry"] <= now:
            return None
        return safe_cache.get(safe_key(authority))

    vulnerable_crossings = sorted(
        name
        for name, authority in changes.items()
        if vulnerable_cache.get(authority["operation"]) == private_result
    )
    safe_hits = sorted(
        name
        for name, authority in changes.items()
        if safe_get(authority, 50) == private_result
    )
    exact_hit = safe_get(original, 50) == private_result
    expired_hit = safe_get(original, 101) == private_result
    return (
        {"crossed_authority_dimensions": vulnerable_crossings},
        {
            "changed_dimension_hits": safe_hits,
            "exact_tuple_hit": exact_hit,
            "expired_at_time_101_hit": expired_hit,
        },
        bool(vulnerable_crossings),
        not safe_hits and exact_hit and not expired_hit,
    )


def _client_identity() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    forged = {
        "name": "trusted-admin-client",
        "capabilities": {"trusted": True, "approval": True},
    }
    untrusted = {"name": "plain-client", "capabilities": {}}

    def vulnerable(metadata: dict[str, Any]) -> bool:
        return metadata["name"].startswith("trusted-") or bool(
            metadata["capabilities"].get("approval")
        )

    def safe(metadata: dict[str, Any]) -> bool:
        del metadata
        return False

    vulnerable_forged = vulnerable(forged)
    vulnerable_plain = vulnerable(untrusted)
    safe_forged = safe(forged)
    safe_plain = safe(untrusted)
    return (
        {
            "forged_decision": vulnerable_forged,
            "untrusted_decision": vulnerable_plain,
            "metadata_changed_outcome": vulnerable_forged != vulnerable_plain,
        },
        {
            "forged_decision": safe_forged,
            "untrusted_decision": safe_plain,
            "same_policy_decision": safe_forged == safe_plain,
        },
        vulnerable_forged != vulnerable_plain,
        safe_forged == safe_plain,
    )


def _rate_limit_rotation() -> tuple[dict[str, Any], dict[str, Any], bool, bool]:
    baseline = {
        "principal": "principal-a",
        "operation": "write",
        "connection": "connection-a",
        "handle": "handle-a",
        "client": "client-a",
        "tool_name": "write-v1",
    }
    rotations = {
        "connection": {**baseline, "connection": "connection-b"},
        "handle": {**baseline, "handle": "handle-b"},
        "client": {**baseline, "client": "client-b"},
        "tool_name": {**baseline, "tool_name": "write-v2"},
    }

    class Limiter:
        def __init__(self, safe: bool) -> None:
            self.safe = safe
            self.seen: set[tuple[str, ...]] = set()

        def allow(self, request: dict[str, str]) -> bool:
            key: tuple[str, ...]
            if self.safe:
                key = (request["principal"], request["operation"])
            else:
                key = (
                    request["principal"],
                    request["operation"],
                    request["connection"],
                    request["handle"],
                    request["client"],
                    request["tool_name"],
                )
            if key in self.seen:
                return False
            self.seen.add(key)
            return True

    vulnerable = Limiter(safe=False)
    vulnerable.allow(baseline)
    vulnerable_resets = sorted(
        name for name, request in rotations.items() if vulnerable.allow(request)
    )
    safe = Limiter(safe=True)
    safe.allow(baseline)
    safe_resets = sorted(name for name, request in rotations.items() if safe.allow(request))
    return (
        {"rotations_restoring_budget": vulnerable_resets},
        {
            "rotations_restoring_budget": safe_resets,
            "principal_operation_budget_exhausted": not safe.allow(baseline),
        },
        bool(vulnerable_resets),
        not safe_resets and not safe.allow(baseline),
    )


_RUNNERS: dict[
    str,
    Callable[[], tuple[dict[str, Any], dict[str, Any], bool, bool]],
] = {
    "SA-001": _handle_theft,
    "SA-002": _handle_tampering,
    "SA-003": _continuation_swap,
    "SA-004": _input_replay,
    "SA-005": _task_cross_tenant,
    "SA-006": _task_revocation,
    "SA-007": _cancellation_race,
    "SA-008": _task_capability_stickiness,
    "SA-009": _parent_request_binding,
    "SA-010": _header_body_binding,
    "SA-011": _cache_isolation,
    "SA-012": _client_identity,
    "SA-013": _rate_limit_rotation,
}


def _official_go_sdk_block(case_id: str, contract: _Contract) -> Evaluation:
    detail = (
        "No exact official Go MCP SDK exists in the bounded local caches; network access "
        "and package installation remain forbidden."
    )
    return Evaluation(
        target_verdict="BLOCKED",
        observations=[
            {
                "case_id": case_id,
                "protocol_status": contract.status,
                "evidence_basis": contract.evidence_basis,
                "pass_oracle": contract.pass_oracle,
                "fail_oracle": contract.fail_oracle,
                "coverage_level": "OFFICIAL_SDK",
                "exact_official_sdk_available": False,
                "simulated_official_sdk_refused": True,
                "synthetic_positive_control_executed": False,
                "synthetic_negative_control_executed": False,
            }
        ],
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        containment_result="NOT_APPLICABLE",
        cleanup_result="NOT_APPLICABLE",
        blocked_kind="ACCESS",
        blocked_detail=detail,
        limitations=[
            "No OFFICIAL_SDK behavior was simulated or inferred from the in-memory fixture model."
        ],
    )


def _cross_sdk_parser(case: dict[str, Any], context: RunContext) -> Evaluation:
    samples = {
        "valid": (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            '"params":{"name":"safe","arguments":{"tenant":"a"}}}'
        ),
        "duplicate_keys": (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            '"method":"resources/read","params":{"name":"safe"}}'
        ),
        "mixed_case": (
            '{"jsonrpc":"2.0","id":1,"Method":"tools/call",'
            '"params":{"name":"safe"}}'
        ),
        "confusable": (
            '{"jsonrpc":"2.0","id":1,"meth\u043ed":"tools/call",'
            '"params":{"name":"safe"}}'
        ),
        "unknown_field": (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            '"params":{"name":"safe","unknown":true}}'
        ),
        "conflicting_top_level_name": (
            '{"jsonrpc":"2.0","id":1,"method":"tools/call",'
            '"params":{"name":"danger","arguments":{"tenant":"a"}},"name":"safe"}'
        ),
    }
    python_code = r"""
import base64
import importlib.metadata
import json
import sys

sys.path.insert(0, "/opt/uv-tools/mcp-server-fetch/lib/python3.11/site-packages")
import mcp.types as types

samples = json.loads(base64.b64decode(sys.argv[1]).decode())
decisions = {}
for name, raw in samples.items():
    try:
        rpc = types.JSONRPCMessage.model_validate_json(raw).root
        request = types.ClientRequest.model_validate(
            rpc.model_dump(by_alias=True, mode="json", exclude_none=True)
        ).root
        decisions[name] = {
            "decision": "ACCEPT",
            "method": request.method,
            "tool_name": getattr(request.params, "name", None),
        }
    except Exception as exc:
        decisions[name] = {
            "decision": "REJECT",
            "error_type": type(exc).__name__,
        }
print(json.dumps({
    "package": "mcp",
    "version": importlib.metadata.version("mcp"),
    "pipeline": [
        "JSONRPCMessage.model_validate_json",
        "ClientRequest.model_validate",
    ],
    "decisions": decisions,
}, sort_keys=True))
"""
    node_code = r"""
const fs = require("node:fs");
const {spawnSync} = require("node:child_process");
(async () => {
  const sdkRoot = "/usr/local/lib/node_modules/@modelcontextprotocol/server-everything/node_modules/@modelcontextprotocol/sdk";
  const packageInfo = JSON.parse(fs.readFileSync(sdkRoot + "/package.json", "utf8"));
  const types = await import(sdkRoot + "/dist/esm/types.js");
  const samples = JSON.parse(process.argv[1]);
  const decisions = {};
  for (const [name, raw] of Object.entries(samples)) {
    try {
      const rpc = types.JSONRPCMessageSchema.parse(JSON.parse(raw));
      const request = types.CallToolRequestSchema.parse(rpc);
      decisions[name] = {
        decision: "ACCEPT",
        method: request.method,
        tool_name: request.params?.name ?? null,
      };
    } catch (error) {
      decisions[name] = {
        decision: "REJECT",
        error_type: error.constructor.name,
      };
    }
  }
  const python = spawnSync(
    "/usr/bin/python3",
    ["-I", "-c", process.argv[2], Buffer.from(process.argv[1]).toString("base64")],
    {
      encoding: "utf8",
      env: {...process.env, PYTHONDONTWRITEBYTECODE: "1"},
    }
  );
  if (python.status !== 0) {
    process.stderr.write(python.stderr);
    process.exit(2);
  }
  process.stdout.write(JSON.stringify({
    typescript: {
      package: packageInfo.name,
      version: packageInfo.version,
      pipeline: [
        "JSONRPCMessageSchema.parse",
        "CallToolRequestSchema.parse",
      ],
      decisions,
    },
    python: JSON.parse(python.stdout),
  }));
})().catch((error) => {
  process.stderr.write(String(error && error.stack || error));
  process.exit(2);
});
"""
    try:
        completed = docker(
            safe_container_arguments(
                name=f"mhai-{context.run_id[-8:]}-sa015",
                run_id=context.run_id,
                image=IMAGE,
                command=[
                    "node",
                    "-e",
                    node_code,
                    json.dumps(samples, sort_keys=True, ensure_ascii=True),
                    python_code,
                ],
            ),
            cwd=context.case_root,
            timeout_seconds=case["timeout_seconds"],
        )
    finally:
        cleanup_labeled_containers(context.run_id, context.case_root)
    if completed.returncode != 0 or completed.timed_out:
        raise RuntimeError(
            "contained cross-SDK parser execution failed: "
            + completed.stderr.decode(errors="replace")
        )
    observed = json.loads(completed.stdout)
    python = observed["python"]
    typescript = observed["typescript"]
    if python["version"] != "1.28.1" or typescript["version"] != "1.29.0":
        raise RuntimeError("qualified image no longer contains the exact SDK versions")
    comparisons: dict[str, dict[str, Any]] = {}
    disagreements: list[str] = []
    for variant in samples:
        left = python["decisions"][variant]
        right = typescript["decisions"][variant]
        same = (
            left.get("decision") == right.get("decision")
            and left.get("method") == right.get("method")
            and left.get("tool_name") == right.get("tool_name")
        )
        comparisons[variant] = {
            "python": left,
            "typescript": right,
            "same_authority_decision": same,
        }
        if not same:
            disagreements.append(variant)
    positive_control = (
        {"decision": "ACCEPT", "tool_name": "danger"}
        != {"decision": "REJECT", "tool_name": None}
    )
    negative_control = comparisons["valid"]["same_authority_decision"]
    conflict = comparisons["conflicting_top_level_name"]
    authority_relevant = (
        conflict["python"].get("decision") == "ACCEPT"
        and conflict["python"].get("tool_name") == "danger"
        and conflict["typescript"].get("decision") == "REJECT"
    )
    return Evaluation(
        target_verdict="FAIL" if disagreements else "PASS",
        observations=[
            {
                "case_id": case["case_id"],
                "protocol_status": _CONTRACTS[case["case_id"]].status,
                "coverage_level": "OFFICIAL_SDK",
                "qualified_container_image": context.bound_qualification()["runtime"][
                    "container_image"
                ],
                "network_mode": "none",
                "package_versions": {
                    "python": f"{python['package']}@{python['version']}",
                    "typescript": (
                        f"{typescript['package']}@{typescript['version']}"
                    ),
                },
                "parser_pipelines": {
                    "python": python["pipeline"],
                    "typescript": typescript["pipeline"],
                },
                "comparisons": comparisons,
                "disagreements": disagreements,
                "authority_relevant_disagreement": authority_relevant,
                "synthetic_positive_control_detected": positive_control,
                "valid_negative_control_agreed": negative_control,
            }
        ],
        positive_control="PASS" if positive_control else "FAIL",
        negative_control="PASS" if negative_control else "FAIL",
        subject_version="package:python-mcp+typescript-sdk@1.28.1+1.29.0",
        limitations=[
            "The result is limited to the exact request-dispatch parsers and versions recorded.",
            "It does not establish an authorization bypass in a particular downstream host.",
            "Different language SDKs use independent release version sequences.",
        ],
    )


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    """Evaluate one SA case within its exact declared evidence ceiling."""

    case_id = case.get("case_id")
    if case_id not in _CONTRACTS:
        raise ValueError(f"unsupported stateless-authority case: {case_id!r}")
    contract = _CONTRACTS[case_id]
    mismatch = _case_contract_error(case, contract)
    if mismatch is not None:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[
                {
                    "case_id": case_id,
                    "catalog_contract_valid": False,
                    "detail": mismatch,
                }
            ],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
            contradictions=[mismatch],
            limitations=["The exact cases.json oracle contract was not executed."],
        )
    if case_id == "SA-014":
        return _official_go_sdk_block(case_id, contract)
    if case_id == "SA-015":
        return _cross_sdk_parser(case, context)

    positive_facts, negative_facts, positive_satisfied, negative_satisfied = _RUNNERS[
        case_id
    ]()
    observation = _observation(
        case_id,
        contract,
        positive_facts,
        negative_facts,
        positive_satisfied,
        negative_satisfied,
    )
    controls_pass = positive_satisfied and negative_satisfied
    contradictions: list[str] = []
    if not positive_satisfied:
        contradictions.append("deliberately vulnerable positive control missed the fail oracle")
    if not negative_satisfied:
        contradictions.append("safe negative control missed the pass oracle")
    return Evaluation(
        target_verdict="PASS" if controls_pass else "FAIL",
        observations=[observation],
        positive_control="PASS" if positive_satisfied else "FAIL",
        negative_control="PASS" if negative_satisfied else "FAIL",
        contradictions=contradictions,
        limitations=[contract.evidence_basis],
    )
