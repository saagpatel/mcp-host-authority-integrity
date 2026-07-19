"""Serial, qualification-gated execution of the complete 57-case program."""

from __future__ import annotations

import hashlib
import json
import os
import shutil
from collections import Counter
from collections.abc import Callable
from pathlib import Path
from typing import Any

from harness.execution import (
    Evaluation,
    RunContext,
    atomic_result,
    build_result,
    fixture_digest,
    new_context,
    utc_now,
)
from harness.ledger import ExecutionLedger
from harness.qualification import ROOT, qualification_receipt_is_current
from harness.redaction import redact
from harness.schema_validation import (
    canonical_digest,
    load_json,
    validate,
    validate_result_contract,
)
from suite_impl import (
    host_confused_deputy,
    integrated_chain,
    local_privilege,
    oauth_identity,
    runtime_truth,
    stateless_authority,
)

Evaluator = Callable[[dict[str, Any], RunContext], Evaluation]

EVALUATORS: dict[str, Evaluator] = {
    "runtime-truth": runtime_truth.evaluate,
    "stateless-authority": stateless_authority.evaluate,
    "host-confused-deputy": host_confused_deputy.evaluate,
    "local-privilege-containment": local_privilege.evaluate,
    "integrated-chain": integrated_chain.evaluate,
}


class ProgramExecutionError(RuntimeError):
    """The complete serial program could not produce a trustworthy manifest."""


def evaluator_for(case: dict[str, Any]) -> Evaluator:
    case_id = case["case_id"]
    if case_id.startswith("OA-"):
        return oauth_identity.evaluate
    try:
        return EVALUATORS[case["execution_family"]]
    except KeyError as exc:
        raise ProgramExecutionError(
            f"no evaluator for {case_id}/{case['execution_family']}"
        ) from exc


def _encode(value: Any) -> bytes:
    return (json.dumps(redact(value), indent=2, sort_keys=True) + "\n").encode()


def _atomic_replace(path: Path, value: Any) -> None:
    encoded = _encode(value)
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    flags = os.O_WRONLY | os.O_CREAT | os.O_EXCL
    if hasattr(os, "O_NOFOLLOW"):
        flags |= os.O_NOFOLLOW
    descriptor = os.open(temporary, flags, 0o600)
    try:
        os.write(descriptor, encoded)
        os.fsync(descriptor)
    finally:
        os.close(descriptor)
    os.replace(temporary, path)


def _error_evaluation(exc: Exception) -> Evaluation:
    return Evaluation(
        target_verdict="UNKNOWN",
        observations=[
            {
                "error_type": type(exc).__name__,
                "detail": str(exc),
            }
        ],
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        cleanup_result="PASS",
        subject_version="not-observed",
        limitations=["The case evaluator raised before its controls completed."],
    )


def _not_run_evaluation(reason: str) -> Evaluation:
    return Evaluation(
        target_verdict="UNKNOWN",
        observations=[
            {
                "executed": False,
                "reason": reason,
                "later_case_after_abort": True,
            }
        ],
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        containment_result="NOT_RUN",
        cleanup_result="NOT_RUN",
        declared_result="NOT_RUN",
        subject_version="not-observed",
        limitations=["The case was not executed after an earlier terminal harness failure."],
    )


def _assert_qualification_binding(context: RunContext) -> dict[str, Any]:
    receipt = context.bound_qualification()
    current, detail = qualification_receipt_is_current(receipt)
    if not current:
        raise ProgramExecutionError(f"bound qualification became stale: {detail}")
    immutable_path = (
        ROOT
        / "results"
        / "runs"
        / context.qualification_run_id
        / "containment-qualification.json"
    )
    immutable = load_json(immutable_path)
    if canonical_digest(immutable) != context.qualification_digest:
        raise ProgramExecutionError("bound per-run qualification receipt changed")
    if fixture_digest() != context.fixture_digest:
        raise ProgramExecutionError("fixture or suite digest changed during execution")
    return receipt


def _assert_closure_epoch_binding(context: RunContext) -> dict[str, Any]:
    receipt = context.bound_closure_epoch()
    immutable_path = (
        ROOT
        / "results"
        / "closure-epochs"
        / context.closure_epoch_id
        / "open.json"
    )
    immutable = load_json(immutable_path)
    if canonical_digest(immutable) != context.closure_epoch_digest:
        raise ProgramExecutionError("bound per-epoch opening receipt changed")
    return receipt


def _validate_manifest(
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
) -> None:
    validate(manifest, load_json(ROOT / "schemas/run-manifest.schema.json"))
    expected_ids = [case["case_id"] for case in cases]
    if manifest["case_ids"] != expected_ids or len(set(expected_ids)) != 57:
        raise ProgramExecutionError("manifest case identity/order is not the exact catalog")
    actual_ids = [item["case_id"] for item in manifest["results"]]
    if actual_ids != expected_ids or len(set(actual_ids)) != 57:
        raise ProgramExecutionError("manifest result identity/order is not exact")
    counts = dict(sorted(Counter(item["result"] for item in manifest["results"]).items()))
    if manifest["result_counts"] != counts:
        raise ProgramExecutionError("manifest result counts do not match its records")
    if manifest["complete"]:
        if (
            manifest["cleanup_result"] != "PASS"
            or manifest["abort_reason"] is not None
            or any(
                item["result"] in {"ERROR", "NOT_IMPLEMENTED", "NOT_RUN"}
                for item in manifest["results"]
            )
        ):
            raise ProgramExecutionError(
                "complete manifest cannot contain terminal harness or coverage gaps"
            )
    elif manifest["abort_reason"] is None:
        raise ProgramExecutionError("incomplete manifest requires an abort reason")


def run_complete_program() -> tuple[dict[str, Any], Path]:
    cases = load_json(ROOT / "cases.json")
    if len(cases) != 57:
        raise ProgramExecutionError(f"expected 57 cases, found {len(cases)}")
    context = new_context()
    qualification = context.bound_qualification()
    closure_epoch = context.bound_closure_epoch()
    started_at = utc_now()
    ledger = ExecutionLedger(ROOT / "results/ledger")
    result_schema = load_json(ROOT / "schemas/result.schema.json")
    run_results = ROOT / "results/runs" / context.run_id / "cases"
    records: list[dict[str, str]] = []
    final_cleanup = "FAIL"
    abort_reason: str | None = None
    cleanup_failed = False
    try:
        for case in cases:
            case_context = context.for_case(case["case_id"])
            case_started = utc_now()
            if abort_reason is not None:
                evaluation = _not_run_evaluation(abort_reason)
            else:
                case_context.case_root.mkdir(parents=True, mode=0o700)
                ledger.claim(context.run_id, case["case_id"])
                try:
                    evaluation = evaluator_for(case)(case, case_context)
                except Exception as exc:
                    evaluation = _error_evaluation(exc)
                try:
                    shutil.rmtree(case_context.case_root)
                    if case_context.case_root.exists():
                        raise ProgramExecutionError(
                            f"{case['case_id']} temporary root remained after cleanup"
                        )
                    if evaluation.cleanup_result != "NOT_APPLICABLE":
                        evaluation.cleanup_result = "PASS"
                except Exception as exc:
                    cleanup_failed = True
                    evaluation.cleanup_result = "FAIL"
                    evaluation.observations.append(
                        {
                            "cleanup_error_type": type(exc).__name__,
                            "cleanup_detail": str(exc),
                        }
                    )
            result = build_result(case, case_context, evaluation, case_started)
            validate_result_contract(result, result_schema, case)
            result_path = run_results / f"{case['case_id']}.json"
            atomic_result(result_path, result)
            encoded = result_path.read_bytes()
            records.append(
                {
                    "case_id": case["case_id"],
                    "result": result["result"],
                    "sha256": hashlib.sha256(encoded).hexdigest(),
                    "path": str(result_path.relative_to(ROOT)),
                }
            )
            if result["result"] == "ERROR" and abort_reason is None:
                abort_reason = (
                    f"terminal case failure at {case['case_id']}; later cases were not executed"
                )
        shutil.rmtree(context.run_root)
        if context.run_root.exists():
            raise ProgramExecutionError("program run root remained after final cleanup")
        final_cleanup = "FAIL" if cleanup_failed else "PASS"
    finally:
        if context.run_root.exists():
            shutil.rmtree(context.run_root, ignore_errors=True)

    if abort_reason is None:
        try:
            qualification = _assert_qualification_binding(context)
            closure_epoch = _assert_closure_epoch_binding(context)
        except Exception as exc:
            abort_reason = str(exc)
    result_counts = dict(sorted(Counter(item["result"] for item in records).items()))
    complete = (
        len(records) == 57
        and final_cleanup == "PASS"
        and abort_reason is None
        and not any(
            item["result"] in {"ERROR", "NOT_IMPLEMENTED", "NOT_RUN"}
            for item in records
        )
    )
    manifest = {
        "program": "MCP Host Authority Integrity Program",
        "run_id": context.run_id,
        "started_at": started_at,
        "finished_at": utc_now(),
        "qualification_digest": canonical_digest(qualification),
        "qualification_run_id": qualification["run_id"],
        "fixture_digest": context.fixture_digest,
        "closure_epoch_id": closure_epoch["epoch_id"],
        "closure_epoch_digest": canonical_digest(closure_epoch),
        "case_count": len(cases),
        "case_ids": [case["case_id"] for case in cases],
        "result_counts": result_counts,
        "results": records,
        "cleanup_result": final_cleanup,
        "complete": complete,
        "abort_reason": abort_reason,
    }
    _validate_manifest(manifest, cases)
    run_path = ROOT / "results/runs" / context.run_id / "run-manifest.json"
    latest_path = ROOT / "results/latest/run-manifest.json"
    atomic_result(run_path, manifest)
    if not complete:
        raise ProgramExecutionError(
            f"program aborted; incomplete manifest preserved at {run_path}: {abort_reason}"
        )
    _assert_qualification_binding(context)
    _assert_closure_epoch_binding(context)
    _atomic_replace(latest_path, manifest)
    return manifest, latest_path
