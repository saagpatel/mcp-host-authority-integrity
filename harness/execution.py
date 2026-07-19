"""Validated result construction and gated suite execution primitives."""

from __future__ import annotations

import hashlib
import json
import secrets
import subprocess
from dataclasses import dataclass, field
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.qualification import qualification_is_current
from harness.browser_policy import browser_refusal
from harness.ledger import write_once
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

    @property
    def case_root(self) -> Path:
        if self.case_id is None:
            return self.run_root
        return self.run_root / self.case_id.lower()

    def for_case(self, case_id: str) -> "RunContext":
        return RunContext(
            run_id=self.run_id,
            run_root=self.run_root,
            browser_mode=self.browser_mode,
            qualification_digest=self.qualification_digest,
            case_id=case_id,
        )


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


def git_head(path: Path) -> str:
    completed = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(path), "rev-parse", "HEAD"],
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
    value = completed.stdout.decode().strip()
    if completed.returncode != 0 or len(value) not in {40, 64}:
        raise RuntimeError(
            f"could not bind read-only Git subject at {path}: "
            f"{completed.stderr.decode(errors='replace')}"
        )
    return value


def subject_version(case: dict[str, Any], evaluation: Evaluation) -> str:
    if evaluation.subject_version is not None:
        return evaluation.subject_version
    coverage = case["coverage_level"]
    if coverage == "LIVE_TARGET":
        targets = {"RT-012": Path("/Users/d/Projects/mcp-trust")}
        return f"git:{git_head(targets[case['case_id']])}"
    if coverage == "ISOLATED_TARGET_COPY":
        targets = {
            "HC-011": Path("/Users/d/Projects/PortfolioCommandCenter"),
            "HC-012": Path("/Users/d/Projects/PortfolioCommandCenter"),
            "LP-007": Path("/Users/d/Projects/AIGCCore"),
            "LP-009": Path("/Users/d/Projects/_claude-worktrees/portfolio-index-forge"),
        }
        commit = git_head(targets[case["case_id"]])
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
    return f"fixture:MHAI-{case['execution_family']}-1@sha256:{fixture_digest()}"


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
        "subject_version": subject_version(case, evaluation),
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
    current, browser_mode = qualification_is_current()
    if not current:
        raise RuntimeError(f"containment qualification is not current: {browser_mode}")
    qualification = load_json(ROOT / "results" / "latest" / "containment-qualification.json")
    run_id = f"run-{int(datetime.now(UTC).timestamp())}-{secrets.token_hex(6)}"
    run_root = ROOT / "work" / "temporary-state" / run_id
    run_root.mkdir(parents=True, mode=0o700)
    return RunContext(
        run_id=run_id,
        run_root=run_root,
        browser_mode=browser_mode,
        qualification_digest=canonical_digest(qualification),
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
