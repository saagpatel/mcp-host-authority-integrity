"""Deterministic additive baseline for the 57-case corpus plus 30 TLG fixtures."""

from __future__ import annotations

import hashlib
import json
from pathlib import Path
from typing import Any

from harness.schema_validation import canonical_digest, load_json, validate
from task_lease_guard.checker import evaluate_catalog, load_catalog

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "task_lease_guard" / "integration-baseline.json"
BASELINE_SCHEMA_PATH = ROOT / "schemas" / "integrated-catalog-baseline.schema.json"

HISTORICAL_CATALOG_SHA256 = "efed9ded61528eedc953e3291c1dbc3c3ed1c35053e8d120e96ad494c4eb75bb"
HISTORICAL_SA_DEFINITIONS_SHA256 = "e4ebe3eb472560cb7f03b507d0fee8a2902ef065048c958f14230c56cddbaf79"
PRIOR_SOURCE_COUNT = 24
PRIOR_SOURCES_SHA256 = "c6336ac508abe58192232d133875eb695960b67c315119f8180c26c11600e341"
HISTORICAL_RESULTS_TREE_SHA256 = "0ae4657e2f5e3eda74d38fa7317d8158aeb1c01b363b43c5d2276e36562e9175"
HISTORICAL_RESULTS_FILE_COUNT = 2057
HISTORICAL_LEDGER_CLAIM_COUNT = 1567
CURRENT_SOURCE_IDS = [
    "MCP-CORE-2026-07-28",
    "MCP-TASKS-EXTENSION-CURRENT",
    "MCP-AUTHORIZATION-2026-07-28",
    "MCP-ELICITATION-2026-07-28",
    "MCP-SAMPLING-2026-07-28",
]


class IntegrationBaselineError(RuntimeError):
    """The additive baseline cannot be generated without rewriting history."""


def _file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _results_tree_binding() -> tuple[str, int, int]:
    paths = sorted(path for path in (ROOT / "results").rglob("*") if path.is_file())
    digest_input = b"".join(
        (
            f"{_file_sha256(path)}  {path.relative_to(ROOT).as_posix()}\n"
        ).encode()
        for path in paths
    )
    ledger_claim_count = sum(
        path.suffix == ".claim" and path.parent == ROOT / "results" / "ledger"
        for path in paths
    )
    return hashlib.sha256(digest_input).hexdigest(), len(paths), ledger_claim_count


def build_integration_baseline() -> dict[str, Any]:
    historical_path = ROOT / "cases.json"
    historical_cases = load_json(historical_path)
    historical_ids = [case["case_id"] for case in historical_cases]
    if len(historical_cases) != 57 or len(set(historical_ids)) != 57:
        raise IntegrationBaselineError("historical catalog is not the exact 57-case inventory")
    if _file_sha256(historical_path) != HISTORICAL_CATALOG_SHA256:
        raise IntegrationBaselineError("historical cases.json digest changed")
    sa_cases = [case for case in historical_cases if case["case_id"].startswith("SA-")]
    if len(sa_cases) != 15 or canonical_digest(sa_cases) != HISTORICAL_SA_DEFINITIONS_SHA256:
        raise IntegrationBaselineError("historical SA-* definitions changed")

    task_catalog = load_catalog()
    task_report = evaluate_catalog(task_catalog)
    task_ids = [case["case_id"] for case in task_catalog["cases"]]
    if task_ids != [f"TLG-{index:03d}" for index in range(1, 31)]:
        raise IntegrationBaselineError("Task Lease Guard namespace is not exactly TLG-001..TLG-030")
    if task_report["suite_result"] != "PASS":
        raise IntegrationBaselineError("Task Lease Guard expectations do not match")
    if set(historical_ids) & set(task_ids):
        raise IntegrationBaselineError("historical and Task Lease Guard namespaces collide")

    registry = load_json(ROOT / "sources" / "source-registry.json")
    validate(registry, load_json(ROOT / "schemas" / "source-registry.schema.json"))
    if registry["sources_digest"] != canonical_digest(registry["sources"]):
        raise IntegrationBaselineError("active source-registry digest is stale")
    prior_sources = registry["sources"][:PRIOR_SOURCE_COUNT]
    if canonical_digest(prior_sources) != PRIOR_SOURCES_SHA256:
        raise IntegrationBaselineError("prior 24 source-registry entries changed")
    current_ids = [source["source_id"] for source in registry["sources"][PRIOR_SOURCE_COUNT:]]
    if current_ids != CURRENT_SOURCE_IDS:
        raise IntegrationBaselineError("current source-registry additions differ from the approved five IDs")

    results_digest, results_count, ledger_claim_count = _results_tree_binding()
    if (
        results_digest != HISTORICAL_RESULTS_TREE_SHA256
        or results_count != HISTORICAL_RESULTS_FILE_COUNT
        or ledger_claim_count != HISTORICAL_LEDGER_CLAIM_COUNT
    ):
        raise IntegrationBaselineError("historical result receipts changed")

    combined_ids = historical_ids + task_ids
    baseline = {
        "schema_version": "MHAI-INTEGRATED-CATALOG-1",
        "baseline_id": "task-lease-guard-2026-08-30",
        "as_of": "2026-08-30",
        "proof_boundary": "LOCAL_SYNTHETIC_FIXTURE",
        "historical_catalog": {
            "namespace": "MHAI-HISTORICAL",
            "path": "cases.json",
            "case_count": len(historical_cases),
            "case_ids": historical_ids,
            "catalog_sha256": HISTORICAL_CATALOG_SHA256,
            "sa_case_count": len(sa_cases),
            "sa_definitions_sha256": HISTORICAL_SA_DEFINITIONS_SHA256,
        },
        "task_lease_guard_catalog": {
            "namespace": "TLG",
            "path": "task_lease_guard/cases.json",
            "case_count": len(task_ids),
            "case_ids": task_ids,
            "catalog_sha256": task_report["catalog_sha256"],
            "suite_result": task_report["suite_result"],
            "outcome_counts": task_report["outcome_counts"],
        },
        "combined_catalog": {
            "case_count": len(combined_ids),
            "ordered_case_ids": combined_ids,
            "namespace_counts": {"MHAI-HISTORICAL": 57, "TLG": 30},
            "identity_sha256": canonical_digest(combined_ids),
        },
        "source_registry": {
            "path": "sources/source-registry.json",
            "prior_source_count": PRIOR_SOURCE_COUNT,
            "prior_sources_sha256": PRIOR_SOURCES_SHA256,
            "current_source_ids": current_ids,
            "sources_digest": registry["sources_digest"],
        },
        "historical_receipts": {
            "path": "results",
            "file_count": results_count,
            "ledger_claim_file_count": ledger_claim_count,
            "tree_sha256": results_digest,
            "immutable": True,
        },
        "claim_ceiling": (
            "Additive local catalog identity and synthetic fixture behavior only; no historical "
            "receipt reinterpretation, installed MCP implementation, transport, provider, "
            "deployment, or exploitable-vulnerability claim."
        ),
    }
    validate(baseline, load_json(BASELINE_SCHEMA_PATH))
    return baseline


def render_integration_baseline() -> str:
    return json.dumps(build_integration_baseline(), indent=2, sort_keys=True) + "\n"
