"""Runtime Truth synthetic fixtures and the bounded live registry observation."""

from __future__ import annotations

import json
import subprocess
import sys
from pathlib import Path
from typing import Any

from harness.execution import Evaluation, RunContext, git_head
from harness.process_control import run_argv, scrubbed_environment
from harness.qualification import ROOT
from harness.schema_validation import load_json
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
    receipt = load_json(ROOT / "results" / "latest" / "containment-qualification.json")
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


def _git_status(path: Path) -> list[str]:
    completed = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(path), "status", "--porcelain=v1"],
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(ROOT / "work" / "temporary-state"),
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        },
        timeout=5,
    )
    if completed.returncode != 0:
        raise RuntimeError(completed.stderr.decode(errors="replace"))
    return completed.stdout.decode().splitlines()


def _registry_self_scan(case: dict[str, Any], context: RunContext) -> Evaluation:
    before_head = git_head(MCP_TRUST)
    before_status = _git_status(MCP_TRUST)
    environment = scrubbed_environment(
        context.case_root / "target-environment",
        {
            "PYTHONPATH": str(MCP_TRUST / "src"),
            "PYTHONDONTWRITEBYTECODE": "1",
        },
    )
    code = """
import json
from mcp_trust.mcp_server import (
    _METHODOLOGY,
    check_server_payload,
    list_servers_payload,
)
listed = json.loads(list_servers_payload())
slug = listed["servers"][0]["slug"]
record = json.loads(check_server_payload(slug))
methodology = _METHODOLOGY
print(json.dumps({
    "server_count": listed["server_count"],
    "sample_slug": slug,
    "sample_grade": record["grade"],
    "sample_transparency": record["transparency"],
    "scan_mode": record.get("scan_mode"),
    "sandbox_applies": record.get("sandbox_applies"),
    "methodology_disclaims_endorsement": "not an endorsement" in methodology.lower(),
    "methodology_limits_runtime_claim": (
        "none of these modes proves runtime behavior" in methodology.lower()
    ),
    "observable_read_functions": [
        "list_servers_payload",
        "check_server_payload",
        "get_methodology",
    ],
}, sort_keys=True))
"""
    completed = run_argv(
        [sys.executable, "-B", "-c", code],
        cwd=context.case_root,
        environment=environment,
        timeout_seconds=case["timeout_seconds"],
        apply_resource_limits=False,
    )
    after_head = git_head(MCP_TRUST)
    after_status = _git_status(MCP_TRUST)
    if completed.returncode != 0:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[
                {
                    "returncode": completed.returncode,
                    "stderr": completed.stderr.decode(errors="replace"),
                }
            ],
            positive_control="FAIL",
            negative_control="NOT_RUN",
            subject_version=f"git:{before_head}",
            limitations=["The live read-only target observation did not execute successfully."],
        )
    payload = json.loads(completed.stdout)
    target_ok = (
        before_head == after_head
        and before_status == after_status
        and payload["server_count"] > 0
        and payload["methodology_disclaims_endorsement"]
        and payload["methodology_limits_runtime_claim"]
    )
    control = controlled_evaluation(
        case,
        context,
        attack_variants=["registry-membership-treated-as-runtime-safety-proof"],
        safe_decisions=[
            ScenarioDecision(
                False,
                "live read APIs were reported with explicit non-endorsement and runtime limits",
            )
        ],
        vulnerable_accepts=["registry-membership-treated-as-runtime-safety-proof"],
    )
    control.subject_version = f"git:{before_head}"
    control.observations.extend(
        [
            {
                "live_target": str(MCP_TRUST),
                "target_head_before": before_head,
                "target_head_after": after_head,
                "target_status_unchanged": before_status == after_status,
                "runtime_observation": payload,
                "mcp_transport_exercised": False,
                "public_annotations_observed": False,
                "evidence_ceiling": "read-only payload behavior only; mutation and isolation unexercised",
            }
        ]
    )
    control.limitations.extend(
        [
            "The MCP transport and FastMCP annotation objects were not available without installing a dependency.",
            "The live call exercised baked read payload functions only and does not prove mutation or isolation behavior.",
        ]
    )
    if not target_ok:
        control.target_verdict = "UNKNOWN"
        control.contradictions.append("live target identity, cleanliness, or honesty-limit control changed")
    return control


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    case_id = case["case_id"]
    if case_id in {f"RT-{index:03d}" for index in range(1, 10)}:
        return _fixture_matrix(case, context)
    if case_id in {"RT-010", "RT-011"}:
        return _qualified_runtime_case(case, context)
    if case_id == "RT-012":
        return _registry_self_scan(case, context)
    raise KeyError(f"unsupported Runtime Truth case: {case_id}")
