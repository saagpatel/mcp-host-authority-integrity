"""Deterministic state-machine checks for synthetic MCP Tasks transcripts."""

from __future__ import annotations

import hashlib
import json
from dataclasses import dataclass, field
from pathlib import Path
from typing import Any

from harness.schema_validation import load_json, validate

ROOT = Path(__file__).resolve().parents[1]
CATALOG_PATH = ROOT / "task_lease_guard" / "cases.json"
SCHEMA_PATH = ROOT / "schemas" / "task-lease-guard-cases.schema.json"

RELEASED_PROFILE = "released-core-2025-11-25"
DRAFT_PROFILE = "current-extension-2026-07-28"
TERMINAL = {"completed", "failed", "cancelled"}
STATUSES = {"working", "input_required", *TERMINAL}
CORE_TRANSITIONS = {
    "working": {"input_required", "completed", "failed", "cancelled"},
    "input_required": {"working", "completed", "failed", "cancelled"},
    "completed": set(),
    "failed": set(),
    "cancelled": set(),
}


@dataclass
class TaskRecord:
    task_id: str
    requestor: str
    context: str | None
    auth_mode: str
    status: str
    created_at_ms: int
    ttl_ms: int | None
    poll_interval_ms: int | None
    last_poll_ms: int | None = None
    terminal_payload_digest: str | None = None
    cancel_sent: bool = False


@dataclass
class GuardState:
    profile: str
    minimum_entropy_bits: int
    declares_task_list: bool
    tasks: dict[str, TaskRecord] = field(default_factory=dict)
    seen_task_ids: set[str] = field(default_factory=set)
    negotiated: bool = False
    core_task_methods: set[str] = field(default_factory=set)
    core_cancel: bool = False
    elicitation_modes: set[str] = field(default_factory=set)
    sampling: bool = False
    checks: list[dict[str, Any]] = field(default_factory=list)
    unknowns: list[dict[str, str]] = field(default_factory=list)

    def pass_check(self, event_index: int, code: str, detail: str) -> None:
        self.checks.append(
            {"event_index": event_index, "code": code, "status": "PASS", "detail": detail}
        )

    def unknown(self, event_index: int, code: str, detail: str) -> None:
        item = {"event_index": str(event_index), "code": code, "detail": detail}
        self.unknowns.append(item)
        self.checks.append(
            {"event_index": event_index, "code": code, "status": "UNKNOWN", "detail": detail}
        )


class ConformanceFailure(ValueError):
    def __init__(self, code: str, detail: str, event_index: int) -> None:
        super().__init__(detail)
        self.code = code
        self.detail = detail
        self.event_index = event_index


def _require(event: dict[str, Any], key: str, event_index: int) -> Any:
    if key not in event:
        raise ConformanceFailure(
            "malformed_fixture_event", f"event is missing required field {key!r}", event_index
        )
    return event[key]


def _task(state: GuardState, event: dict[str, Any], event_index: int) -> TaskRecord:
    task_id = str(_require(event, "task_id", event_index))
    task = state.tasks.get(task_id)
    if task is None:
        raise ConformanceFailure(
            "task_not_created", "task operation occurred before durable creation", event_index
        )
    return task


def _check_access(
    state: GuardState, task: TaskRecord, event: dict[str, Any], event_index: int
) -> None:
    requestor = str(_require(event, "requestor", event_index))
    context = event.get("context")
    if task.auth_mode == "context_bound":
        if requestor != task.requestor or context != task.context:
            raise ConformanceFailure(
                "authorization_context_mismatch",
                "task operation was not bound to the creating requestor and authorization context",
                event_index,
            )
        state.pass_check(event_index, "authorization_context_match", "task access remained bound")
        return
    if requestor != task.requestor:
        state.unknown(
            event_index,
            "requestor_binding_unavailable",
            "the fixture transport has no authorization context capable of distinguishing callers",
        )
    else:
        state.pass_check(
            event_index,
            "bearer_task_id_present",
            "no-authorization access used the original synthetic requestor label",
        )


def _negotiate(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    state.negotiated = True
    state.core_task_methods = set(event.get("task_methods", []))
    state.core_cancel = bool(event.get("task_cancel", False))
    state.elicitation_modes = set(event.get("elicitation_modes", []))
    state.sampling = bool(event.get("sampling", False))
    state.pass_check(event_index, "capabilities_recorded", "synthetic capabilities were frozen")


def _create(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    if not state.negotiated:
        raise ConformanceFailure(
            "capability_negotiation_missing",
            "task creation preceded capability negotiation",
            event_index,
        )
    method = str(_require(event, "method", event_index))
    if state.profile == RELEASED_PROFILE:
        if method not in state.core_task_methods or not event.get("request_task_augmented", False):
            raise ConformanceFailure(
                "undeclared_task_capability",
                "released-core task creation lacked the negotiated method capability or augmentation",
                event_index,
            )
    elif state.profile == DRAFT_PROFILE:
        if method != "tools/call":
            raise ConformanceFailure(
                "unsupported_task_method",
                "the draft extension currently supports only tools/call",
                event_index,
            )
        if not event.get("server_extension_discovered", False) or not event.get(
            "per_request_client_extension", False
        ):
            raise ConformanceFailure(
                "undeclared_task_capability",
                "draft task creation lacked server discovery or the current request capability",
                event_index,
            )
        if not event.get("durably_created", False):
            raise ConformanceFailure(
                "task_not_durable_at_creation",
                "CreateTaskResult was emitted before tasks/get could resolve the task",
                event_index,
            )
    else:
        raise ConformanceFailure("unsupported_protocol_profile", state.profile, event_index)

    task_id = str(_require(event, "task_id", event_index))
    if task_id in state.seen_task_ids:
        raise ConformanceFailure(
            "task_id_reuse", "task ID was reused within the fixture lifetime", event_index
        )
    expected_issuer = "receiver" if state.profile == RELEASED_PROFILE else "server"
    if event.get("id_issuer") != expected_issuer:
        raise ConformanceFailure(
            "invalid_task_id_issuer",
            f"{state.profile} task IDs must be generated by the {expected_issuer}",
            event_index,
        )
    auth_mode = str(_require(event, "auth_mode", event_index))
    crypto_random = bool(event.get("crypto_random", False))
    entropy_bits = int(event.get("entropy_bits", 0))
    entropy_required = state.profile == DRAFT_PROFILE or auth_mode == "none"
    if entropy_required and not crypto_random:
        raise ConformanceFailure(
            "insufficient_task_id_entropy",
            "task ID was generated by a predictable or enumerable mechanism",
            event_index,
        )
    if entropy_required and entropy_bits < state.minimum_entropy_bits:
        state.unknown(
            event_index,
            "quantitative_entropy_threshold_unspecified",
            "the specification requires unguessability but defines no numeric bit threshold",
        )
    if auth_mode == "none" and state.declares_task_list:
        raise ConformanceFailure(
            "unauthenticated_task_listing",
            "a receiver unable to identify requestors declared task listing",
            event_index,
        )

    status = str(_require(event, "status", event_index))
    if status not in STATUSES:
        raise ConformanceFailure("invalid_task_status", status, event_index)
    if state.profile == RELEASED_PROFILE and status != "working":
        raise ConformanceFailure(
            "invalid_initial_state", "released-core tasks must begin in working", event_index
        )
    record = TaskRecord(
        task_id=task_id,
        requestor=str(_require(event, "requestor", event_index)),
        context=event.get("context"),
        auth_mode=auth_mode,
        status=status,
        created_at_ms=int(_require(event, "at_ms", event_index)),
        ttl_ms=event.get("ttl_ms"),
        poll_interval_ms=event.get("poll_interval_ms"),
    )
    state.tasks[task_id] = record
    state.seen_task_ids.add(task_id)
    state.pass_check(event_index, "task_created", "task seed state passed creation checks")


def _poll(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    task = _task(state, event, event_index)
    _check_access(state, task, event, event_index)
    at_ms = int(_require(event, "at_ms", event_index))
    if task.ttl_ms is not None and at_ms > task.created_at_ms + task.ttl_ms:
        if event.get("served", False):
            state.unknown(
                event_index,
                "expired_task_retention_unspecified",
                "the applicable protocol permits but does not require deletion after TTL expiry",
            )
        else:
            state.pass_check(event_index, "expired_task_rejected", "expired task was not replayed")
        return
    poll_baseline = task.created_at_ms if task.last_poll_ms is None else task.last_poll_ms
    if task.poll_interval_ms is not None and at_ms - poll_baseline < task.poll_interval_ms:
        raise ConformanceFailure(
            "poll_interval_ignored", "polling occurred before the suggested interval", event_index
        )
    task.last_poll_ms = at_ms
    if "next_poll_interval_ms" in event:
        next_interval = int(event["next_poll_interval_ms"])
        if next_interval < 0:
            raise ConformanceFailure(
                "invalid_poll_interval", "poll interval cannot be negative", event_index
            )
        task.poll_interval_ms = next_interval
    state.pass_check(event_index, "poll_accepted", "poll respected lifetime and interval checks")


def _transition(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    task = _task(state, event, event_index)
    if event.get("actor") not in {"receiver", "server"}:
        raise ConformanceFailure(
            "forged_task_state", "a non-receiver attempted to author task state", event_index
        )
    new_status = str(_require(event, "status", event_index))
    if new_status not in STATUSES:
        raise ConformanceFailure("invalid_task_status", new_status, event_index)
    if task.status in TERMINAL:
        raise ConformanceFailure(
            "terminal_state_mutation", "a terminal task attempted another transition", event_index
        )
    if state.profile == RELEASED_PROFILE and new_status not in CORE_TRANSITIONS[task.status]:
        raise ConformanceFailure(
            "invalid_task_transition", f"{task.status} cannot transition to {new_status}", event_index
        )
    failure_kind = event.get("failure_kind")
    if new_status == "failed":
        if state.profile == DRAFT_PROFILE and failure_kind != "json_rpc_error":
            raise ConformanceFailure(
                "failure_status_mismatch",
                "draft failed status is reserved for JSON-RPC execution errors",
                event_index,
            )
        if state.profile == RELEASED_PROFILE and failure_kind not in {
            "json_rpc_error",
            "tool_result_is_error",
        }:
            raise ConformanceFailure(
                "failure_status_mismatch",
                "released-core failed status requires an underlying execution error",
                event_index,
            )
    if new_status in {"completed", "failed"}:
        digest = event.get("payload_digest")
        if not isinstance(digest, str) or not digest:
            raise ConformanceFailure(
                "terminal_payload_missing", "terminal task lacked its final result or error", event_index
            )
        task.terminal_payload_digest = digest
    task.status = new_status
    state.pass_check(event_index, "state_transition_accepted", f"task moved to {new_status}")


def _cancel(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    task = _task(state, event, event_index)
    _check_access(state, task, event, event_index)
    if state.profile == RELEASED_PROFILE:
        if not state.core_cancel:
            raise ConformanceFailure(
                "undeclared_cancel_capability", "tasks/cancel was not negotiated", event_index
            )
        if task.status in TERMINAL:
            raise ConformanceFailure(
                "terminal_task_cancelled", "released-core terminal cancellation must be rejected", event_index
            )
        if event.get("response_status") != "cancelled":
            raise ConformanceFailure(
                "cancel_state_not_committed",
                "released-core cancellation response preceded cancelled status",
                event_index,
            )
        task.status = "cancelled"
    else:
        if not event.get("acknowledged", False):
            raise ConformanceFailure(
                "cancel_not_acknowledged", "draft cooperative cancellation lacked empty ack", event_index
            )
    task.cancel_sent = True
    state.pass_check(event_index, "cancellation_accepted", "profile-specific cancellation contract held")


def _result(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    task = _task(state, event, event_index)
    _check_access(state, task, event, event_index)
    delivery = str(_require(event, "delivery", event_index))
    if state.profile == DRAFT_PROFILE and delivery == "tasks/result":
        raise ConformanceFailure(
            "unsupported_result_retrieval",
            "the draft extension removed tasks/result in favor of inline tasks/get results",
            event_index,
        )
    if state.profile == DRAFT_PROFILE and delivery != "inline_tasks_get":
        raise ConformanceFailure("invalid_result_delivery", delivery, event_index)
    if state.profile == RELEASED_PROFILE and delivery != "tasks/result":
        raise ConformanceFailure("invalid_result_delivery", delivery, event_index)
    if task.status not in TERMINAL:
        if event.get("blocked", False):
            state.pass_check(event_index, "nonterminal_result_blocked", "premature result did not return")
            return
        raise ConformanceFailure(
            "premature_result_release", "nonterminal task returned a final result", event_index
        )
    if task.status == "cancelled" and task.terminal_payload_digest is None:
        if event.get("served", False):
            state.unknown(
                event_index,
                "cancelled_result_custody_unspecified",
                "the fixture does not contain a bound underlying terminal payload",
            )
        else:
            state.pass_check(event_index, "cancelled_result_absent", "no unbound result was released")
        return
    if event.get("payload_digest") != task.terminal_payload_digest:
        raise ConformanceFailure(
            "terminal_result_mismatch",
            "retrieved terminal payload did not match receiver-authored custody",
            event_index,
        )
    if state.profile == RELEASED_PROFILE and event.get("related_task_id") != task.task_id:
        raise ConformanceFailure(
            "related_task_mismatch", "tasks/result omitted or forged related-task metadata", event_index
        )
    state.pass_check(event_index, "terminal_result_bound", "terminal result matched task custody")


def _input_request(state: GuardState, event: dict[str, Any], event_index: int) -> None:
    task = _task(state, event, event_index)
    _check_access(state, task, event, event_index)
    if event.get("related_task_id") != task.task_id:
        raise ConformanceFailure(
            "related_task_mismatch", "nested request was not associated with its task", event_index
        )
    kind = str(_require(event, "kind", event_index))
    if kind == "elicitation":
        mode = str(event.get("mode", "form"))
        if mode not in state.elicitation_modes:
            raise ConformanceFailure(
                "undeclared_nested_capability", "elicitation mode was not declared", event_index
            )
        if mode == "form" and event.get("sensitive", False):
            raise ConformanceFailure(
                "sensitive_form_elicitation",
                "sensitive information was requested through form elicitation",
                event_index,
            )
    elif kind == "sampling":
        if not state.sampling:
            raise ConformanceFailure(
                "undeclared_nested_capability", "sampling capability was not declared", event_index
            )
        if not event.get("human_review_available", False):
            raise ConformanceFailure(
                "sampling_without_human_review",
                "task nesting did not preserve the sampling trust model",
                event_index,
            )
    else:
        raise ConformanceFailure("unsupported_nested_request", kind, event_index)
    if not event.get("same_trust_model", False):
        raise ConformanceFailure(
            "task_trust_escalation", "nested task request bypassed standalone trust handling", event_index
        )
    state.pass_check(event_index, "nested_request_bound", f"{kind} preserved capabilities and trust")


HANDLERS = {
    "negotiate": _negotiate,
    "create": _create,
    "poll": _poll,
    "transition": _transition,
    "cancel": _cancel,
    "result": _result,
    "input_request": _input_request,
}


def evaluate_case(case: dict[str, Any], minimum_entropy_bits: int = 128) -> dict[str, Any]:
    fixture = case["fixture"]
    state = GuardState(
        profile=case["profile"],
        minimum_entropy_bits=minimum_entropy_bits,
        declares_task_list=bool(fixture["declares_task_list"]),
    )
    failure: ConformanceFailure | None = None
    for event_index, event in enumerate(fixture["events"]):
        try:
            op = str(_require(event, "op", event_index))
            handler = HANDLERS.get(op)
            if handler is None:
                raise ConformanceFailure("unsupported_fixture_event", op, event_index)
            handler(state, event, event_index)
        except ConformanceFailure as exc:
            state.checks.append(
                {
                    "event_index": exc.event_index,
                    "code": exc.code,
                    "status": "FAIL",
                    "detail": exc.detail,
                }
            )
            failure = exc
            break
    if failure is not None:
        outcome = "FAIL"
        reasons = [failure.code]
    elif state.unknowns:
        outcome = "UNKNOWN"
        reasons = sorted({item["code"] for item in state.unknowns})
    else:
        outcome = "PASS"
        reasons = ["all_applicable_checks_passed"]
    return {
        "case_id": case["case_id"],
        "outcome": outcome,
        "reason_codes": reasons,
        "profile": case["profile"],
        "protocol_status": case["protocol_status"],
        "proof_boundary": "LOCAL_SYNTHETIC_FIXTURE",
        "checks": state.checks,
        "claim_ceiling": case["claim_ceiling"],
    }


def load_catalog(path: Path = CATALOG_PATH) -> dict[str, Any]:
    catalog = load_json(path)
    validate(catalog, load_json(SCHEMA_PATH))
    case_ids = [case["case_id"] for case in catalog["cases"]]
    if len(case_ids) != len(set(case_ids)):
        raise ValueError("task lease case IDs must be unique")
    return catalog


def evaluate_catalog(catalog: dict[str, Any]) -> dict[str, Any]:
    minimum_entropy_bits = int(catalog["policy"]["minimum_entropy_bits"])
    results = [evaluate_case(case, minimum_entropy_bits) for case in catalog["cases"]]
    expected = {case["case_id"]: case for case in catalog["cases"]}
    mismatches = []
    for result in results:
        case = expected[result["case_id"]]
        if result["outcome"] != case["expected_outcome"] or not set(
            case["expected_reason_codes"]
        ).issubset(result["reason_codes"]):
            mismatches.append(
                {
                    "case_id": result["case_id"],
                    "expected_outcome": case["expected_outcome"],
                    "actual_outcome": result["outcome"],
                    "expected_reason_codes": case["expected_reason_codes"],
                    "actual_reason_codes": result["reason_codes"],
                }
            )
    counts = {name: sum(result["outcome"] == name for result in results) for name in ("PASS", "FAIL", "UNKNOWN")}
    binding = hashlib.sha256(
        json.dumps(catalog, sort_keys=True, separators=(",", ":")).encode("utf-8")
    ).hexdigest()
    return {
        "schema_version": "TaskLeaseGuardReportV1",
        "catalog_sha256": binding,
        "case_count": len(results),
        "outcome_counts": counts,
        "expectation_mismatches": mismatches,
        "suite_result": "PASS" if not mismatches else "FAIL",
        "proof_boundary": "LOCAL_SYNTHETIC_FIXTURE",
        "claim_ceiling": (
            "Checker and fixture behavior only; no installed client/server, transport, "
            "deployment, interoperability, or exploitable-vulnerability claim."
        ),
        "results": results,
    }
