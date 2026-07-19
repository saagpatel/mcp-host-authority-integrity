"""Runtime Truth synthetic fixtures and the bounded live registry observation."""

from __future__ import annotations

import hashlib
import json
from typing import Any

from harness.execution import ROOT, Evaluation, RunContext
from harness.process_control import (
    cleanup_labeled_containers,
    docker,
    safe_container_arguments,
)
from harness.qualification import IMAGE
from suite_impl.common import ScenarioDecision, controlled_evaluation, deny_all


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
    frozen = context.frozen_target(case["case_id"])
    archive = frozen["archive"]
    if not archive.get("created") or not archive.get("fidelity_proven"):
        return Evaluation(
            target_verdict="BLOCKED",
            blocked_kind="ACCESS",
            blocked_detail="No fidelity-proven immutable mcp-trust archive is bound to this run.",
            observations=[
                {
                    "target_head": frozen["head"],
                    "archive_created": archive.get("created", False),
                    "archive_fidelity_proven": archive.get("fidelity_proven", False),
                    "target_code_executed": False,
                }
            ],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
            subject_version=f"git:{frozen['head']}",
        )
    archive_path = (ROOT / archive["path"]).resolve()
    if ROOT.resolve() not in archive_path.parents:
        raise RuntimeError("frozen mcp-trust archive escaped the program root")
    if hashlib.sha256(archive_path.read_bytes()).hexdigest() != archive["sha256"]:
        raise RuntimeError("frozen mcp-trust archive digest changed")

    python_code = r"""
import asyncio
import hashlib
import json
import sys

sys.path.insert(0, "/opt/uv-tools/mcp-server-fetch/lib/python3.11/site-packages")
sys.path.insert(0, "/subject/mcp-trust.zip/src")

from mcp_trust.mcp_server import build_server

def plain(value):
    if hasattr(value, "model_dump"):
        return value.model_dump(mode="json", by_alias=True, exclude_none=True)
    if isinstance(value, (list, tuple)):
        return [plain(item) for item in value]
    if isinstance(value, dict):
        return {key: plain(item) for key, item in value.items()}
    return value

def text_from(value):
    candidate = plain(value)
    queue = [candidate]
    while queue:
        current = queue.pop(0)
        if isinstance(current, dict):
            if isinstance(current.get("text"), str):
                return current["text"]
            queue.extend(current.values())
        elif isinstance(current, list):
            queue.extend(current)
    raise RuntimeError("tool call did not return text")

async def main():
    app = build_server()
    tools = await app.list_tools()
    listed_raw = text_from(await app.call_tool("list_servers", {}))
    listed = json.loads(listed_raw)
    if listed["server_count"] < 1:
        raise RuntimeError("registry returned no public records")
    slug = listed["servers"][0]["slug"]
    known_raw = text_from(await app.call_tool("check_server", {"slug": slug}))
    known = json.loads(known_raw)
    missing_raw = text_from(
        await app.call_tool("check_server", {"slug": "synthetic-missing-server"})
    )
    missing = json.loads(missing_raw)
    print(json.dumps({
        "tool_names": sorted(tool.name for tool in tools),
        "tool_annotations": {
            tool.name: plain(tool.annotations) if tool.annotations is not None else None
            for tool in tools
        },
        "server_count": listed["server_count"],
        "known_slug_round_trip": known.get("slug") == slug,
        "known_record_has_grade": isinstance(known.get("grade"), str),
        "missing_record_rejected": isinstance(missing.get("error"), str),
        "list_payload_sha256": hashlib.sha256(listed_raw.encode()).hexdigest(),
        "known_payload_sha256": hashlib.sha256(known_raw.encode()).hexdigest(),
        "missing_payload_sha256": hashlib.sha256(missing_raw.encode()).hexdigest(),
    }, sort_keys=True))

asyncio.run(main())
"""
    node_code = (
        "const {spawnSync}=require('node:child_process');"
        f"const code={json.dumps(python_code)};"
        "const result=spawnSync('/usr/bin/python3',['-I','-c',code],"
        "{encoding:'utf8',env:{...process.env,PYTHONDONTWRITEBYTECODE:'1'}});"
        "if(result.status!==0){process.stderr.write(result.stderr);process.exit(2);}"
        "process.stdout.write(result.stdout);"
    )
    try:
        completed = docker(
            safe_container_arguments(
                name=f"mhai-{context.run_id[-8:]}-rt012",
                run_id=context.run_id,
                image=IMAGE,
                command=["node", "-e", node_code],
                readonly_mounts=((archive_path, "/subject/mcp-trust.zip"),),
            ),
            cwd=context.case_root,
            timeout_seconds=case["timeout_seconds"],
        )
    finally:
        cleanup_labeled_containers(context.run_id, context.case_root)
    if completed.returncode != 0 or completed.timed_out:
        raise RuntimeError(
            "contained mcp-trust observation failed: "
            + completed.stderr.decode(errors="replace")
        )
    observed = json.loads(completed.stdout)
    expected_tools = ["check_server", "get_methodology", "list_servers"]
    runtime_satisfied = (
        observed["tool_names"] == expected_tools
        and observed["server_count"] > 0
        and observed["known_slug_round_trip"]
        and observed["known_record_has_grade"]
        and observed["missing_record_rejected"]
    )
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=["represent-unobserved-mutation-or-isolation-as-proven"],
        safe_decisions=[
            ScenarioDecision(
                False,
                "only exact read behavior and public annotations are reported",
            )
        ],
        vulnerable_accepts=["represent-unobserved-mutation-or-isolation-as-proven"],
        observations=[
            {
                "target_head": frozen["head"],
                "target_tree": frozen["tree"],
                "archive_sha256": archive["sha256"],
                "archive_tree_manifest_sha256": archive["tree_manifest_sha256"],
                "archive_fidelity_proven": True,
                "qualified_container_image": context.bound_qualification()["runtime"][
                    "container_image"
                ],
                "network_mode": "none",
                "target_mount": "read-only",
                "observable_read_behavior": observed,
                "runtime_oracle_satisfied": runtime_satisfied,
                "mutation_behavior_proven": False,
                "isolation_behavior_proven": False,
            }
        ],
        limitations=[
            "The result covers the exact archived commit and exercised read-only tool paths only.",
            "No mutation, credential, live database, deployment, or runtime isolation claim was tested.",
        ],
    )
    evaluation.subject_version = f"git:{frozen['head']}"
    if not runtime_satisfied:
        evaluation.target_verdict = "FAIL"
    return evaluation


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    case_id = case["case_id"]
    if case_id in {f"RT-{index:03d}" for index in range(1, 10)}:
        return _fixture_matrix(case, context)
    if case_id in {"RT-010", "RT-011"}:
        return _qualified_runtime_case(case, context)
    if case_id == "RT-012":
        return _registry_self_scan(case, context)
    raise KeyError(f"unsupported Runtime Truth case: {case_id}")
