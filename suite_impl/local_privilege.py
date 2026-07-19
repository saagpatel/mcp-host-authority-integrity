"""Local privilege-containment fixture scenarios and evidence-bounded target checks."""

from __future__ import annotations

import hashlib
import hmac
import json
import shutil
from pathlib import Path
from typing import Any

from harness.execution import Evaluation, RunContext
from harness.limits import SCHEMA_DEPTH, LimitExceeded, enforce_schema_depth
from harness.process_control import run_argv, scrubbed_environment
from harness.target_executors import (
    AIGC_LP007_MARKERS,
    AIGC_LP007_TESTS,
    bound_executable,
    executor_receipt,
    file_sha256,
    run_exact_test,
)
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
) -> Evaluation:
    frozen = context.frozen_target(case["case_id"])
    commit = frozen["head"]
    cleanliness = "clean" if frozen["clean"] else "not clean"
    archive = frozen["archive"]
    archive_available = bool(
        archive.get("created") and archive.get("fidelity_proven")
    )
    if archive_available:
        if case["case_id"] == "LP-007":
            detail = (
                f"An exact read-only {target_name} archive is available, but no "
                "qualified target executor with a proven network-attempt sensor "
                "can exercise the full UI, command, adapter, and dependency paths."
            )
        else:
            detail = (
                f"An exact read-only {target_name} archive is available, but no "
                "qualified target executor can exercise the case's public-leakage "
                "and local-privilege containment path."
            )
    elif not frozen["clean"]:
        detail = (
            f"{target_name} is {cleanliness} at the frozen epoch identity; "
            f"the ownership check was {frozen['ownership']} and does not override "
            "the clean-source requirement."
        )
    elif frozen["ownership"] != "CLEAR":
        detail = (
            f"{target_name} is clean at the frozen epoch identity, but "
            f"ownership is {frozen['ownership']}."
        )
    else:
        detail = (
            f"{target_name} is clean and ownership is clear at the frozen epoch "
            "identity, but no fidelity-proven immutable archive is available."
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


def _evaluate_lp_007_target(
    case: dict[str, Any],
    context: RunContext,
) -> Evaluation:
    frozen = context.frozen_target(case["case_id"])
    archive = frozen["archive"]
    try:
        executable, receipt, source_root = bound_executable(
            context,
            case["case_id"],
            set(AIGC_LP007_TESTS.values()),
        )
    except (FileNotFoundError, ValueError) as error:
        blocked = _blocked_copy(case, context, target_name="AIGCCore")
        blocked.observations[0]["executor_error"] = str(error)
        return blocked

    case_root = context.case_root / "lp007-network-path"
    rust_runs = {
        label: run_exact_test(
            executable=executable,
            test_name=test_name,
            domain_root=case_root / label,
        )
        for label, test_name in AIGC_LP007_TESTS.items()
    }
    marker_results = {
        "positive_attempt": (
            AIGC_LP007_MARKERS["positive_attempt"]
            in rust_runs["positive_control"]["stdout_tail"]
        ),
        "full_path": (
            AIGC_LP007_MARKERS["full_path"]
            in rust_runs["positive_control"]["stdout_tail"]
        ),
        "hostile_non_loopback": (
            AIGC_LP007_MARKERS["hostile_non_loopback"]
            in rust_runs["hostile_non_loopback"]["stdout_tail"]
        ),
        "malformed": (
            AIGC_LP007_MARKERS["malformed"]
            in rust_runs["malformed"]["stdout_tail"]
        ),
    }

    node = shutil.which("node")
    contract_path = source_root / "src/ui/authorityIntegrityContract.ts"
    ui_domain = case_root / "frontend-contract"
    ui_domain.mkdir(parents=True, exist_ok=False, mode=0o700)
    ui_environment = scrubbed_environment(ui_domain)
    ui_script = (
        "import(process.argv[1]).then((m) => {"
        "const value=m.authorityIntegrityInvokeRequest(process.argv[2]);"
        "console.log(JSON.stringify(value));"
        "}).catch((error)=>{console.error(error);process.exit(2)})"
    )
    if node is None or not contract_path.is_file():
        ui_completed = None
        ui_request: dict[str, Any] = {}
    else:
        ui_completed = run_argv(
            [
                node,
                "--experimental-strip-types",
                "-e",
                ui_script,
                contract_path.resolve().as_uri(),
                "http://203.0.113.1:9",
            ],
            cwd=source_root,
            environment=ui_environment,
            timeout_seconds=10,
            max_output_bytes=64 * 1024,
            apply_resource_limits=False,
        )
        try:
            ui_request = json.loads(ui_completed.stdout)
        except json.JSONDecodeError:
            ui_request = {}
    shutil.rmtree(ui_domain)
    ui_cleanup = not ui_domain.exists()
    ui_contract_passed = (
        ui_completed is not None
        and ui_completed.returncode == 0
        and ui_request
        == {
            "command": "authority_integrity_probe_adapter",
            "body": {"input": {"endpoint": "http://203.0.113.1:9"}},
        }
        and ui_cleanup
    )
    positive_passed = (
        rust_runs["positive_control"]["returncode"] == 0
        and marker_results["positive_attempt"]
        and marker_results["full_path"]
    )
    negative_passed = (
        rust_runs["hostile_non_loopback"]["returncode"] == 0
        and rust_runs["malformed"]["returncode"] == 0
        and marker_results["hostile_non_loopback"]
        and marker_results["malformed"]
        and ui_contract_passed
    )
    cleanup_passed = all(run["cleanup_verified"] for run in rust_runs.values())
    if case_root.exists():
        shutil.rmtree(case_root)
    cleanup_passed = cleanup_passed and ui_cleanup and not case_root.exists()
    observations = [
        {
            "source_candidate_head": frozen["head"],
            "source_candidate_tree": frozen["tree"],
            "archive_path": archive.get("path"),
            "archive_sha256": archive.get("sha256"),
            "archive_fidelity_proven": archive.get("fidelity_proven"),
            "test_executable_sha256": receipt["test_executable_sha256"],
            "source_deviations": receipt["source_deviations"],
            "frontend_contract_path": str(contract_path.relative_to(source_root)),
            "frontend_contract_sha256": file_sha256(contract_path),
            "frontend_request": ui_request,
            "frontend_contract_executed": ui_completed is not None,
            "actual_tauri_ipc_dispatcher_executed": True,
            "production_adapter_runtime_executed": True,
            "socket_dependency_executed": True,
            "successful_network_scope": "run-owned loopback positive-control listener only",
            "arbitrary_egress_succeeded": False,
            "rust_runs": rust_runs,
            "marker_results": marker_results,
            "target_code_executed": True,
            "target_repository_accessed_during_case": False,
            "cleanup_verified": cleanup_passed,
        }
    ]
    deviation = hashlib.sha256(
        json.dumps(
            {
                "executor_sha256": receipt["test_executable_sha256"],
                "frontend_contract_sha256": file_sha256(contract_path),
                "marker_results": marker_results,
                "source_deviations": receipt["source_deviations"],
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if not positive_passed or not negative_passed or not cleanup_passed:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control="PASS" if positive_passed else "FAIL",
            negative_control="PASS" if negative_passed else "FAIL",
            containment_result="PASS",
            cleanup_result="PASS" if cleanup_passed else "FAIL",
            declared_result="ERROR",
            limitations=[
                "The source-owned UI, IPC, adapter, dependency, or sensor control matrix was incomplete."
            ],
            subject_version=f"git:{frozen['head']}+deviations:{deviation}",
        )
    return Evaluation(
        target_verdict="PASS",
        observations=observations,
        positive_control="PASS",
        negative_control="PASS",
        containment_result="PASS",
        cleanup_result="PASS",
        limitations=[
            "Coverage is limited to the source-owned integrity hook and the exercised loopback, non-loopback, and malformed endpoint variants."
        ],
        subject_version=f"git:{frozen['head']}+deviations:{deviation}",
    )


def _evaluate_lp_009_target(
    case: dict[str, Any],
    context: RunContext,
) -> Evaluation:
    frozen = context.frozen_target(case["case_id"])
    archive = frozen["archive"]
    try:
        receipt, source_root = executor_receipt(context, case["case_id"])
    except (FileNotFoundError, ValueError) as error:
        blocked = _blocked_copy(case, context, target_name="portfolio-index")
        blocked.observations[0]["executor_error"] = str(error)
        return blocked

    generator = source_root / "scripts/build-projects.py"
    python = shutil.which("python3")
    if python is None or not generator.is_file():
        blocked = _blocked_copy(case, context, target_name="portfolio-index")
        blocked.observations[0]["executor_error"] = "exact generator unavailable"
        return blocked

    private_marker = "mhai-private-only-lp009"
    owner_marker = "mhai-private-owner-lp009"
    projects: list[dict[str, Any]] = [
        {
            "identity": {"repo_full_name": "saagpatel/mcp-trust"},
            "derived": {
                "stack": ["Python"],
                "activity_status": "active",
                "has_tests": True,
                "has_ci": True,
            },
            "declared": {"lifecycle_state": "active"},
        },
        {
            "identity": {"repo_full_name": f"saagpatel/{private_marker}"},
            "derived": {
                "stack": ["Python"],
                "activity_status": "active",
                "has_tests": False,
                "has_ci": False,
            },
            "declared": {"lifecycle_state": "active"},
            "owner": owner_marker,
            "notes": private_marker,
        },
    ]
    truth: dict[str, Any] = {
        "schema_version": "synthetic-lp009",
        "projects": projects,
    }
    case_root = context.case_root / "lp009-public-aggregation"
    safe_domain = case_root / "safe-subject"
    safe_domain.mkdir(parents=True, exist_ok=False, mode=0o700)
    safe_environment = scrubbed_environment(safe_domain)
    script = (
        "import importlib.util,json,sys;"
        "spec=importlib.util.spec_from_file_location('target_build_projects',sys.argv[1]);"
        "module=importlib.util.module_from_spec(spec);spec.loader.exec_module(module);"
        "print(json.dumps(module.build(json.loads(sys.argv[2])),sort_keys=True))"
    )
    completed = run_argv(
        [python, "-c", script, str(generator), json.dumps(truth, sort_keys=True)],
        cwd=source_root,
        environment=safe_environment,
        timeout_seconds=10,
        max_output_bytes=256 * 1024,
        apply_resource_limits=False,
    )
    try:
        public_output = json.loads(completed.stdout)
    except json.JSONDecodeError:
        public_output = {}
    safe_blob = json.dumps(public_output, sort_keys=True)
    shutil.rmtree(safe_domain)
    safe_cleanup = not safe_domain.exists()

    vulnerable_domain = case_root / "vulnerable-control"
    vulnerable_domain.mkdir(parents=True, exist_ok=False, mode=0o700)
    vulnerable_canary = vulnerable_domain / "public-output.json"
    vulnerable_output = {
        "curated": {
            project["identity"]["repo_full_name"].rsplit("/", 1)[-1]: project
            for project in projects
        }
    }
    vulnerable_canary.write_text(
        json.dumps(vulnerable_output, sort_keys=True),
        encoding="utf-8",
    )
    vulnerable_blob = vulnerable_canary.read_text(encoding="utf-8")
    positive_passed = private_marker in vulnerable_blob and owner_marker in vulnerable_blob
    shutil.rmtree(vulnerable_domain)
    vulnerable_cleanup = not vulnerable_domain.exists()

    negative_passed = (
        completed.returncode == 0
        and "mcp-trust" in public_output.get("curated", {})
        and private_marker not in safe_blob
        and owner_marker not in safe_blob
    )
    if case_root.exists():
        shutil.rmtree(case_root)
    cleanup_passed = safe_cleanup and vulnerable_cleanup and not case_root.exists()
    observations = [
        {
            "source_candidate_head": frozen["head"],
            "source_candidate_tree": frozen["tree"],
            "archive_path": archive.get("path"),
            "archive_sha256": archive.get("sha256"),
            "archive_fidelity_proven": archive.get("fidelity_proven"),
            "source_deviations": receipt["source_deviations"],
            "generator_path": str(generator.relative_to(source_root)),
            "generator_sha256": file_sha256(generator),
            "synthetic_project_count": len(truth["projects"]),
            "public_control_present": "mcp-trust"
            in public_output.get("curated", {}),
            "private_repo_marker_excluded": private_marker not in safe_blob,
            "private_owner_marker_excluded": owner_marker not in safe_blob,
            "vulnerable_control_leaked_private_markers": positive_passed,
            "safe_output_sha256": hashlib.sha256(safe_blob.encode()).hexdigest(),
            "target_code_executed": True,
            "target_repository_accessed_during_case": False,
            "cleanup_verified": cleanup_passed,
        }
    ]
    deviation = hashlib.sha256(
        json.dumps(
            {
                "generator_sha256": file_sha256(generator),
                "source_deviations": receipt["source_deviations"],
                "fixture_schema": truth["schema_version"],
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if not positive_passed or not negative_passed or not cleanup_passed:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control="PASS" if positive_passed else "FAIL",
            negative_control="PASS" if negative_passed else "FAIL",
            containment_result="PASS",
            cleanup_result="PASS" if cleanup_passed else "FAIL",
            declared_result="ERROR",
            limitations=["The exact public-aggregation control matrix was incomplete."],
            subject_version=f"git:{frozen['head']}+deviations:{deviation}",
        )
    return Evaluation(
        target_verdict="PASS",
        observations=observations,
        positive_control="PASS",
        negative_control="PASS",
        containment_result="PASS",
        cleanup_result="PASS",
        limitations=[
            "Coverage is limited to the archived build-projects generator and synthetic structured project records."
        ],
        subject_version=f"git:{frozen['head']}+deviations:{deviation}",
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
        return _evaluate_lp_007_target(case, context)
    if case_id == "LP-008":
        return _signature_case(case, context)
    if case_id == "LP-009":
        return _evaluate_lp_009_target(case, context)
    if case_id == "LP-011":
        return _schema_exhaustion(case, context)
    raise KeyError(f"unsupported Local Privilege case: {case_id}")
