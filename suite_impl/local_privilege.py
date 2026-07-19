"""Local privilege-containment fixture scenarios and evidence-bounded target checks."""

from __future__ import annotations

import hashlib
import hmac
from pathlib import Path
from typing import Any

from harness.execution import Evaluation, RunContext
from harness.limits import SCHEMA_DEPTH, LimitExceeded, enforce_schema_depth
from suite_impl.common import ScenarioDecision, controlled_evaluation, deny_all

BRIDGE_DB = Path("/Users/d/Projects/bridge-db")


def _matrix_case(case: dict[str, Any], context: RunContext) -> Evaluation:
    variants: dict[str, list[str]] = {
        "LP-001": [
            "cookie-disclosure-cross-port",
            "cookie-replay-approve",
            "cookie-replay-send",
            "cookie-replay-apply",
        ],
        "LP-002": [
            "child-outside-subtree",
            "sibling-authority",
            "parent-authority-escalation",
        ],
        "LP-003": [
            "sibling-replay",
            "later-run-replay",
            "modified-arguments",
            "different-server",
            "expired-approval",
        ],
        "LP-005": [
            "direct-sibling-call",
            "synthetic-credential-pivot",
            "claimed-principal-pivot",
        ],
        "LP-010": [
            "https-ref",
            "file-ref",
            "loopback-ref",
            "private-address-ref",
            "redirected-ref",
        ],
    }
    reasons = {
        "LP-001": "session audience includes exact fixture origin and port",
        "LP-002": "delegation is intersected with the granted subtree and principal",
        "LP-003": "approval binds run, principal, server, operation, arguments, and expiry",
        "LP-005": "host mediation binds each server to a distinct synthetic principal",
        "LP-010": "external references are rejected before resolver I/O",
    }
    case_variants = variants[case["case_id"]]
    return controlled_evaluation(
        case,
        context,
        attack_variants=case_variants,
        safe_decisions=deny_all(case_variants, reasons[case["case_id"]]),
        vulnerable_accepts=case_variants,
        observations=[
            {
                "authority_tuple_dimensions": [
                    "principal",
                    "server",
                    "operation",
                    "arguments",
                    "scope",
                    "expiry",
                ],
                "exact_tuple_required": True,
            }
        ],
    )


def _environment_case(case: dict[str, Any], context: RunContext) -> Evaluation:
    receipt = context.bound_qualification()
    cq11 = next(item for item in receipt["checks"] if item["check_id"] == "CQ-011")
    variants = [
        "secret-shaped-environment-key",
        "undeclared-descriptor",
        "socket-descriptor",
        "host-working-directory",
        "ambient-control-endpoint",
    ]
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "exact scrubbed environment and descriptor allowlist"),
        vulnerable_accepts=variants,
        observations=[
            {
                "qualification_run_id": receipt["run_id"],
                "cq_011_result": cq11["result"],
                "active_inventory": cq11["observations"][0],
            }
        ],
        limitations=[
            "Environment inheritance evidence is bound to the exact qualified container image."
        ],
    )
    if cq11["result"] != "PASS":
        evaluation.positive_control = "FAIL"
        evaluation.target_verdict = "UNKNOWN"
    return evaluation


def _bridge_static_case(case: dict[str, Any], context: RunContext) -> Evaluation:
    paths = [
        BRIDGE_DB / "src/bridge_db/auth.py",
        BRIDGE_DB / "src/bridge_db/tools/activity.py",
        BRIDGE_DB / "src/bridge_db/tools/snapshots.py",
    ]
    digest = hashlib.sha256()
    observations: list[dict[str, Any]] = []
    for path in paths:
        data = path.read_bytes()
        digest.update(path.name.encode())
        digest.update(b"\0")
        digest.update(data)
        observations.append(
            {
                "path_name": path.name,
                "sha256": hashlib.sha256(data).hexdigest(),
                "principal_reference_count": data.count(b"principal"),
            }
        )
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=["fixture-authorization-represented-as-live-isolation-proof"],
        safe_decisions=[
            ScenarioDecision(
                False,
                "static and fixture evidence cannot establish live tenant isolation",
            )
        ],
        vulnerable_accepts=["fixture-authorization-represented-as-live-isolation-proof"],
        observations=[
            {
                "read_only_contract_files": observations,
                "runtime_tenant_isolation_proven": False,
                "fixture_authorization_matrix_scope": "fixture-only",
                "claim_boundary_preserved": True,
            }
        ],
        limitations=[
            "Static evidence cannot prove BridgeDB runtime read isolation.",
            "No BridgeDB tool call or database mutation was made for this case.",
        ],
    )
    evaluation.subject_version = f"snapshot:sha256:{digest.hexdigest()}"
    return evaluation


def _blocked_copy(
    case: dict[str, Any],
    context: RunContext,
    *,
    target_name: str,
    ownership_detail: str,
) -> Evaluation:
    frozen = context.frozen_target(case["case_id"])
    commit = frozen["head"]
    cleanliness = "clean" if frozen["clean"] else "not clean"
    archive = frozen["archive"]
    archive_available = bool(
        archive.get("created") and archive.get("fidelity_proven")
    )
    detail = (
        (
            f"An exact read-only {target_name} archive is available, but no "
            "program-owned locked dependency set and qualified target executor "
            "can exercise the full claimed runtime paths."
        )
        if archive_available
        else (
            f"{target_name} is {cleanliness} at the frozen epoch identity; "
            f"{ownership_detail}"
        )
    )
    deviation = hashlib.sha256(
        f"{case['case_id']}:{commit}:copy-not-created".encode()
    ).hexdigest()
    return Evaluation(
        target_verdict="BLOCKED",
        blocked_kind="ACCESS",
        blocked_detail=detail,
        observations=[
            {
                "source_candidate_head": commit,
                "source_candidate_tree": frozen["tree"],
                "source_clean_at_epoch_open": frozen["clean"],
                "ownership": frozen["ownership"],
                "ownership_basis": frozen["ownership_basis"],
                "isolated_copy_created": archive_available,
                "archive_sha256": archive.get("sha256"),
                "target_access": (
                    "program archive receipt only"
                    if archive_available
                    else "frozen closure-epoch identity only"
                ),
                "target_code_executed": False,
                "overclaim_refused": True,
            }
        ],
        subject_version=f"git:{commit}+deviations:{deviation}",
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        containment_result="NOT_APPLICABLE",
        cleanup_result="NOT_APPLICABLE",
        limitations=["No behavior of the live checkout or an isolated copy was executed."],
    )


def _signature_case(case: dict[str, Any], context: RunContext) -> Evaluation:
    variants = ["adjacent-attacker-key", "forged-manifest", "publisher-name-collision"]
    attacker_key = b"synthetic-attacker-key"
    forged_manifest = b'{"publisher":"trusted-looking","server":"fixture"}'
    adjacent_signature = hmac.new(attacker_key, forged_manifest, hashlib.sha256).hexdigest()
    adjacent_verifies = hmac.compare_digest(
        adjacent_signature,
        hmac.new(attacker_key, forged_manifest, hashlib.sha256).hexdigest(),
    )
    independent_anchor_matches = False
    return controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "adjacent key lacks an independent publisher anchor"),
        vulnerable_accepts=variants,
        observations=[
            {
                "adjacent_bundle_internally_consistent": adjacent_verifies,
                "independent_publisher_anchor_matches": independent_anchor_matches,
                "bundle_accepted": False,
            }
        ],
    )


def _schema_exhaustion(case: dict[str, Any], context: RunContext) -> Evaluation:
    variants = ["over-depth", "recursive-shape", "oversized-branch", "many-errors"]
    value: object = "leaf"
    for _ in range(SCHEMA_DEPTH + 1):
        value = {"next": value}
    try:
        enforce_schema_depth(value)
    except LimitExceeded:
        hostile_stopped = True
    else:
        hostile_stopped = False
    enforce_schema_depth({"valid": ["follow-up"]})
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "bounded validator rejects before its configured ceiling"),
        vulnerable_accepts=variants,
        observations=[
            {
                "over_depth_stopped": hostile_stopped,
                "valid_follow_up_completed": True,
                "worker_survived": False,
            }
        ],
    )
    if not hostile_stopped:
        evaluation.target_verdict = "FAIL"
    return evaluation


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    case_id = case["case_id"]
    if case_id in {"LP-001", "LP-002", "LP-003", "LP-005", "LP-010"}:
        return _matrix_case(case, context)
    if case_id == "LP-004":
        return _environment_case(case, context)
    if case_id == "LP-006":
        return _bridge_static_case(case, context)
    if case_id == "LP-007":
        return _blocked_copy(
            case,
            context,
            target_name="AIGCCore",
            ownership_detail=(
                "source ownership is not clear enough to create or execute a "
                "program-owned archive."
            ),
        )
    if case_id == "LP-008":
        return _signature_case(case, context)
    if case_id == "LP-009":
        return _blocked_copy(
            case,
            context,
            target_name="portfolio-index",
            ownership_detail=(
                f"the shared {context.frozen_target(case_id)['branch']} worktree "
                "has an active owner."
            ),
        )
    if case_id == "LP-011":
        return _schema_exhaustion(case, context)
    raise KeyError(f"unsupported Local Privilege case: {case_id}")
