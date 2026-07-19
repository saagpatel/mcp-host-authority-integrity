"""Runtime Truth synthetic fixtures and the bounded live registry observation."""

from __future__ import annotations

import hashlib
from pathlib import Path
from typing import Any

from harness.execution import Evaluation, RunContext, git_head
from suite_impl.common import ScenarioDecision, controlled_evaluation, deny_all

MCP_TRUST = Path("/Users/d/Projects/mcp-trust")


def _fixture_matrix(case: dict[str, Any], context: RunContext) -> Evaluation:
    case_id = case["case_id"]
    variants: dict[str, list[str]] = {
        "RT-001": ["harmless-list-metadata-hidden-authority-body"],
        "RT-002": ["harmless-list-metadata-executable-resource-body"],
        "RT-003": ["non-mutating-description-runtime-canary-write"],
        "RT-004": ["readOnlyHint-true-runtime-canary-write"],
        "RT-005": ["openWorldHint-false-run-owned-loopback-attempt"],
        "RT-006": ["later-page-contradictory-entry", "repeated-cursor-loop"],
        "RT-007": ["schema-change", "annotation-change", "identity-change", "effect-change"],
        "RT-008": ["client-label-a", "client-label-b", "forged-trusted-label"],
        "RT-009": ["same-tool-name-server-a", "same-tool-name-server-b"],
    }
    details: dict[str, dict[str, Any]] = {
        "RT-001": {
            "descriptor": "Summarize a synthetic document.",
            "retrieved_body_class": "authority-seeking",
            "body_observed": True,
        },
        "RT-002": {
            "descriptor": "Static synthetic text.",
            "retrieved_body_class": "executable-looking",
            "body_observed": True,
        },
        "RT-003": {
            "declared_effect": "none",
            "runtime_effect": "program-canary-write-attempt",
            "mismatch_reported": True,
        },
        "RT-004": {
            "readOnlyHint": True,
            "runtime_effect": "program-canary-write-attempt",
            "hint_treated_as_untrusted": True,
        },
        "RT-005": {
            "openWorldHint": False,
            "runtime_effect": "run-owned-loopback-attempt",
            "hint_treated_as_untrusted": True,
        },
        "RT-006": {
            "page_count": 3,
            "opaque_cursors_followed": 2,
            "contradictory_entry_page": 3,
            "cursor_loop_rejected": True,
        },
        "RT-007": {
            "list_changed_received": True,
            "fresh_discovery_required": True,
            "prior_approval_reused": False,
        },
        "RT-008": {
            "exact_client_labels": ["fixture-client-a@1", "fixture-client-b@1"],
            "differential_recorded": True,
            "client_info_used_for_authorization": False,
        },
        "RT-009": {
            "composite_keys": ["server-a::collide", "server-b::collide"],
            "selected_origin": "server-a",
            "ambiguous_name_only_lookup_rejected": True,
        },
    }
    case_variants = variants[case_id]
    decisions = deny_all(case_variants, "runtime evidence contradicted the declared authority input")
    if case_id == "RT-008":
        decisions = [
            ScenarioDecision(False, "differential observed and bound to the exact client label"),
            ScenarioDecision(False, "differential observed and bound to the exact client label"),
            ScenarioDecision(False, "self-asserted client label is not an authorization input"),
        ]
    return controlled_evaluation(
        case,
        context,
        attack_variants=case_variants,
        safe_decisions=decisions,
        vulnerable_accepts=case_variants,
        observations=[details[case_id]],
    )


def _qualified_runtime_case(case: dict[str, Any], context: RunContext) -> Evaluation:
    receipt = context.bound_qualification()
    checks = {item["check_id"]: item for item in receipt["checks"]}
    if case["case_id"] == "RT-010":
        required = ["CQ-004", "CQ-005", "CQ-009"]
        variants = ["controller-death", "emergency-stop", "delayed-process-action"]
        observation = {
            "qualification_run_id": receipt["run_id"],
            "qualification_checks": {key: checks[key]["result"] for key in required},
            "controller_death": checks["CQ-004"]["observations"][0],
            "emergency_stop": checks["CQ-005"]["observations"][0],
            "cleanup": checks["CQ-009"]["observations"][-1],
        }
    else:
        required = ["CQ-003", "CQ-008", "CQ-011"]
        variants = [
            "host-filesystem",
            "metadata-network",
            "dns",
            "privilege",
            "process-limit",
            "environment-inheritance",
        ]
        observation = {
            "qualification_run_id": receipt["run_id"],
            "qualification_checks": {key: checks[key]["result"] for key in required},
            "network_boundary": checks["CQ-003"]["observations"][0],
            "container_limits": checks["CQ-008"]["observations"][0],
            "environment_inventory": checks["CQ-011"]["observations"][0],
        }
    if any(checks[key]["result"] != "PASS" for key in required):
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[observation],
            positive_control="FAIL",
            negative_control="NOT_RUN",
            limitations=["The exact containment qualification did not satisfy this case oracle."],
        )
    return controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "active qualification probe denied the prohibited effect"),
        vulnerable_accepts=variants,
        observations=[observation],
        limitations=[
            "The case reuses active probes from the exact current containment qualification."
        ],
    )


def _registry_self_scan(case: dict[str, Any], context: RunContext) -> Evaluation:
    head = git_head(MCP_TRUST)
    boundary_digest = hashlib.sha256(
        f"{case['case_id']}:{head}:live-target-code-not-executed".encode()
    ).hexdigest()
    return Evaluation(
        target_verdict="BLOCKED",
        blocked_kind="ACCESS",
        blocked_detail=(
            "Live mcp-trust code cannot execute outside the qualified containment and "
            "effect boundary; no immutable isolated copy was approved."
        ),
        observations=[
            {
                "live_target": str(MCP_TRUST),
                "target_head": head,
                "target_code_executed": False,
                "isolated_copy_created": False,
                "effect_broker_bypassed": False,
                "blocked_boundary_digest": boundary_digest,
                "overclaim_refused": True,
            }
        ],
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        containment_result="NOT_APPLICABLE",
        cleanup_result="NOT_APPLICABLE",
        subject_version=f"git:{head}",
        limitations=[
            "No public annotation or observable live read behavior was exercised.",
            "The LIVE_TARGET claim remains unproven until an approved immutable contained copy exists.",
        ],
    )


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    case_id = case["case_id"]
    if case_id in {f"RT-{index:03d}" for index in range(1, 10)}:
        return _fixture_matrix(case, context)
    if case_id in {"RT-010", "RT-011"}:
        return _qualified_runtime_case(case, context)
    if case_id == "RT-012":
        return _registry_self_scan(case, context)
    raise KeyError(f"unsupported Runtime Truth case: {case_id}")
