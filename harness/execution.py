"""Validated result construction and gated suite execution primitives."""

from __future__ import annotations

import hashlib
import json
import secrets
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.browser_policy import browser_refusal
from harness.closure_epoch import target_observation, validate_open_receipt
from harness.ledger import write_once
from harness.qualification import (
    qualification_receipt_is_current,
    validate_qualification_contract,
)
from harness.redaction import redact
from harness.schema_validation import (
    canonical_digest,
    load_json,
    validate_result_contract,
)

ROOT = Path(__file__).resolve().parents[1]


@dataclass
class Evaluation:
    target_verdict: str
    observations: list[dict[str, Any]]
    limitations: list[str] = field(default_factory=list)
    positive_control: str = "PASS"
    negative_control: str = "PASS"
    containment_result: str = "PASS"
    cleanup_result: str = "PASS"
    contradictions: list[str] = field(default_factory=list)
    blocked_kind: str | None = None
    blocked_detail: str | None = None
    declared_result: str | None = None
    subject_version: str | None = None


@dataclass(frozen=True)
class RunContext:
    run_id: str
    run_root: Path
    browser_mode: str
    qualification_digest: str
    case_id: str | None = None
    qualification_run_id: str = ""
    qualification_receipt_json: str = "{}"
    fixture_digest: str = ""
    closure_epoch_id: str = ""
    closure_epoch_digest: str = ""
    closure_epoch_receipt_json: str = "{}"

    @property
    def case_root(self) -> Path:
        if self.case_id is None:
            return self.run_root
        return self.run_root / self.case_id.lower()

    def for_case(self, case_id: str) -> RunContext:
        return RunContext(
            run_id=self.run_id,
            run_root=self.run_root,
            browser_mode=self.browser_mode,
            qualification_digest=self.qualification_digest,
            case_id=case_id,
            qualification_run_id=self.qualification_run_id,
            qualification_receipt_json=self.qualification_receipt_json,
            fixture_digest=self.fixture_digest,
            closure_epoch_id=self.closure_epoch_id,
            closure_epoch_digest=self.closure_epoch_digest,
            closure_epoch_receipt_json=self.closure_epoch_receipt_json,
        )

    def bound_qualification(self) -> dict[str, Any]:
        receipt = json.loads(self.qualification_receipt_json)
        validate_qualification_contract(receipt)
        if (
            canonical_digest(receipt) != self.qualification_digest
            or receipt["run_id"] != self.qualification_run_id
        ):
            raise RuntimeError("qualification snapshot no longer matches the run binding")
        return receipt

    def bound_closure_epoch(self) -> dict[str, Any]:
        receipt = json.loads(self.closure_epoch_receipt_json)
        validate_open_receipt(receipt)
        if (
            canonical_digest(receipt) != self.closure_epoch_digest
            or receipt["epoch_id"] != self.closure_epoch_id
        ):
            raise RuntimeError("closure epoch snapshot no longer matches the run binding")
        return receipt

    def frozen_target(self, case_id: str) -> dict[str, Any]:
        return target_observation(self.bound_closure_epoch(), case_id)


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def file_digest(paths: list[Path]) -> str:
    digest = hashlib.sha256()
    for path in sorted(paths):
        digest.update(str(path.relative_to(ROOT)).encode())
        digest.update(b"\0")
        digest.update(path.read_bytes())
        digest.update(b"\0")
    return digest.hexdigest()


def fixture_digest() -> str:
    paths = [
        path
        for directory in (ROOT / "suite_impl", ROOT / "fixtures")
        if directory.exists()
        for path in directory.rglob("*")
        if path.is_file() and "__pycache__" not in path.parts and not path.name.endswith(".pyc")
    ]
    return file_digest(paths)


def subject_version(
    case: dict[str, Any],
    evaluation: Evaluation,
    context: RunContext,
) -> str:
    if evaluation.subject_version is not None:
        return evaluation.subject_version
    coverage = case["coverage_level"]
    if coverage == "LIVE_TARGET":
        return f"git:{context.frozen_target(case['case_id'])['head']}"
    if coverage == "ISOLATED_TARGET_COPY":
        commit = context.frozen_target(case["case_id"])["head"]
        deviations = hashlib.sha256(
            f"{case['case_id']}:{commit}:no-copy-created-blocked".encode()
        ).hexdigest()
        return f"git:{commit}+deviations:{deviations}"
    if coverage == "OFFICIAL_SDK":
        return "package:github.com/modelcontextprotocol/go-sdk@unavailable"
    if coverage == "STATIC_EVIDENCE_ONLY":
        digest = hashlib.sha256(
            f"{case['case_id']}:{case['exact_subject_claim']}".encode()
        ).hexdigest()
        return f"snapshot:sha256:{digest}"
    digest = context.fixture_digest or fixture_digest()
    return f"fixture:MHAI-{case['execution_family']}-1@sha256:{digest}"


def deterministic_declared_result(evaluation: Evaluation) -> str:
    if evaluation.declared_result is not None:
        return evaluation.declared_result
    if (
        "FAIL" in {evaluation.positive_control, evaluation.negative_control}
        or evaluation.containment_result == "FAIL"
        or evaluation.cleanup_result == "FAIL"
    ):
        return "ERROR"
    if evaluation.blocked_kind == "AUTHORITY":
        return "BLOCKED_BY_AUTHORITY"
    if evaluation.blocked_kind is not None:
        return "BLOCKED_BY_ACCESS"
    if (
        "NOT_RUN" in {evaluation.positive_control, evaluation.negative_control}
        or evaluation.containment_result == "NOT_RUN"
        or evaluation.cleanup_result == "NOT_RUN"
    ):
        return "ERROR"
    if evaluation.contradictions or evaluation.target_verdict == "UNKNOWN":
        return "UNKNOWN"
    return evaluation.target_verdict


def build_result(
    case: dict[str, Any],
    context: RunContext,
    evaluation: Evaluation,
    started_at: str,
) -> dict[str, Any]:
    blocked_reason = None
    if evaluation.blocked_kind is not None:
        blocked_reason = {
            "kind": evaluation.blocked_kind,
            "detail": evaluation.blocked_detail or "blocked by the execution boundary",
        }
    result = {
        "case_id": case["case_id"],
        "run_id": context.run_id,
        "case_definition_digest": canonical_digest(case),
        "oracle_version": "MHAI-ORACLE-1",
        "subject": case["exact_subject_claim"],
        "subject_version": subject_version(case, evaluation, context),
        "coverage_level": case["coverage_level"],
        "protocol_status": case["protocol_status"],
        "started_at": started_at,
        "finished_at": utc_now(),
        "observations": redact(evaluation.observations),
        "target_verdict": evaluation.target_verdict,
        "control_results": {
            "positive": evaluation.positive_control,
            "negative": evaluation.negative_control,
        },
        "containment_result": evaluation.containment_result,
        "cleanup_result": evaluation.cleanup_result,
        "contradictions": evaluation.contradictions,
        "result": deterministic_declared_result(evaluation),
        "evidence": [
            {
                "kind": "validated-scenario-observation",
                "observation_digest": canonical_digest(redact(evaluation.observations)),
                "qualification_digest": context.qualification_digest,
            }
        ],
        "limitations": [*case["limitations"], *evaluation.limitations],
        "blocked_reason": blocked_reason,
    }
    validate_result_contract(
        result,
        load_json(ROOT / "schemas" / "result.schema.json"),
        case,
    )
    return result


def atomic_result(path: Path, value: Any) -> None:
    clean = redact(value)
    encoded = (json.dumps(clean, indent=2, sort_keys=True) + "\n").encode()
    write_once(path, encoded)


def new_context() -> RunContext:
    qualification_path = ROOT / "results" / "latest" / "containment-qualification.json"
    qualification = load_json(qualification_path)
    current, browser_mode = qualification_receipt_is_current(qualification)
    if not current:
        raise RuntimeError(f"containment qualification is not current: {browser_mode}")
    qualification_digest = canonical_digest(qualification)
    immutable_path = (
        ROOT
        / "results"
        / "runs"
        / qualification["run_id"]
        / "containment-qualification.json"
    )
    immutable = load_json(immutable_path)
    if canonical_digest(immutable) != qualification_digest:
        raise RuntimeError("latest qualification differs from its per-run receipt")
    qualification_json = json.dumps(
        qualification,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    closure_path = ROOT / "results" / "latest" / "closure-epoch-open.json"
    closure_epoch = load_json(closure_path)
    validate_open_receipt(closure_epoch)
    closure_digest = canonical_digest(closure_epoch)
    immutable_closure_path = (
        ROOT
        / "results"
        / "closure-epochs"
        / closure_epoch["epoch_id"]
        / "open.json"
    )
    immutable_closure = load_json(immutable_closure_path)
    if canonical_digest(immutable_closure) != closure_digest:
        raise RuntimeError("latest closure epoch differs from its immutable receipt")
    closure_json = json.dumps(
        closure_epoch,
        sort_keys=True,
        separators=(",", ":"),
        ensure_ascii=True,
    )
    run_id = f"run-{int(datetime.now(UTC).timestamp())}-{secrets.token_hex(6)}"
    run_root = ROOT / "work" / "temporary-state" / run_id
    run_root.mkdir(parents=True, mode=0o700)
    return RunContext(
        run_id=run_id,
        run_root=run_root,
        browser_mode=browser_mode,
        qualification_digest=qualification_digest,
        qualification_run_id=qualification["run_id"],
        qualification_receipt_json=qualification_json,
        fixture_digest=fixture_digest(),
        closure_epoch_id=closure_epoch["epoch_id"],
        closure_epoch_digest=closure_digest,
        closure_epoch_receipt_json=closure_json,
    )


def browser_block(case: dict[str, Any], context: RunContext) -> Evaluation | None:
    refusal = browser_refusal(case, context.browser_mode)
    if refusal is not None:
        return Evaluation(
            target_verdict="BLOCKED",
            blocked_kind=refusal["blocked_kind"],
            blocked_detail=refusal["blocked_detail"],
            observations=[
                {
                    "browser_required": refusal["browser_required"],
                    "browser_mode": context.browser_mode,
                    "unsafe_fallback_refused": refusal["unsafe_fallback_refused"],
                }
            ],
            limitations=["No browser or embedded-webview behavior was executed."],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
        )
    return None
