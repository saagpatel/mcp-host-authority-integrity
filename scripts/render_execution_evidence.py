#!/usr/bin/env python3
"""Render human-readable closeout evidence from one complete immutable run."""

from __future__ import annotations

import argparse
import hashlib
import json
import sys
from collections import Counter, defaultdict
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.schema_validation import (  # noqa: E402 - direct-script path bootstrap
    canonical_digest,
    load_json,
    validate,
    validate_result_contract,
)


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def markdown_cell(value: str) -> str:
    return value.replace("|", "\\|").replace("\n", " ").strip()


def read_and_validate() -> tuple[
    dict[str, Any],
    dict[str, Any],
    dict[str, Any],
    list[dict[str, Any]],
    list[dict[str, Any]],
]:
    manifest_path = ROOT / "results/latest/run-manifest.json"
    qualification_path = ROOT / "results/latest/containment-qualification.json"
    closure_path = ROOT / "results/latest/closure-epoch-close.json"
    manifest = load_json(manifest_path)
    qualification = load_json(qualification_path)
    closure = load_json(closure_path)
    cases = load_json(ROOT / "cases.json")
    cases_by_id = {case["case_id"]: case for case in cases}

    validate(manifest, load_json(ROOT / "schemas/run-manifest.schema.json"))
    validate(qualification, load_json(ROOT / "schemas/qualification.schema.json"))
    validate(closure, load_json(ROOT / "schemas/closure-epoch-close.schema.json"))
    if not manifest["complete"] or manifest["abort_reason"] is not None:
        raise ValueError("latest run is not complete")
    if manifest["cleanup_result"] != "PASS":
        raise ValueError("latest run cleanup did not pass")
    if manifest["qualification_run_id"] != qualification["run_id"]:
        raise ValueError("latest run is not bound to the latest qualification receipt")
    if (
        manifest["closure_epoch_id"] != closure["epoch_id"]
        or manifest["closure_epoch_digest"] != closure["open_digest"]
        or manifest["run_id"] != closure["run_id"]
        or closure["run_manifest_sha256"] != canonical_digest(manifest)
        or closure["result"] != "PASS_WITH_HISTORICAL_EXCEPTION"
        or closure["no_forbidden_mutation_gate"] != "PASS"
        or not closure["safely_obtainable_coverage_executed"]
        or closure["historical_exceptions"] != ["SE-001"]
        or closure["historical_exception_repaired"]
    ):
        raise ValueError("latest run is not bound to a passing closure epoch")
    if manifest["case_ids"] != [case["case_id"] for case in cases]:
        raise ValueError("manifest case order differs from the immutable catalog")
    if len(cases_by_id) != 57:
        raise ValueError("immutable catalog does not contain exactly 57 unique cases")

    result_schema = load_json(ROOT / "schemas/result.schema.json")
    results: list[dict[str, Any]] = []
    run_root = (ROOT / "results/runs" / manifest["run_id"]).resolve()
    for item in manifest["results"]:
        expected_path = (
            ROOT
            / "results/runs"
            / manifest["run_id"]
            / "cases"
            / f"{item['case_id']}.json"
        ).resolve()
        recorded_path = (ROOT / item["path"]).resolve()
        if recorded_path != expected_path or run_root not in recorded_path.parents:
            raise ValueError(f"{item['case_id']}: result path is outside the exact run")
        encoded = recorded_path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != item["sha256"]:
            raise ValueError(f"{item['case_id']}: result hash mismatch")
        result = json.loads(encoded)
        validate_result_contract(result, result_schema, cases_by_id[item["case_id"]])
        if result["run_id"] != manifest["run_id"] or result["result"] != item["result"]:
            raise ValueError(f"{item['case_id']}: manifest/result binding mismatch")
        results.append(result)

    counts = dict(sorted(Counter(result["result"] for result in results).items()))
    if counts != manifest["result_counts"] or len(results) != 57:
        raise ValueError("manifest result counts do not match the 57 validated results")
    return manifest, qualification, closure, cases, results


def render_summary(
    manifest: dict[str, Any],
    qualification: dict[str, Any],
    closure: dict[str, Any],
    cases: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> str:
    cases_by_id = {case["case_id"]: case for case in cases}
    by_suite: dict[str, Counter[str]] = defaultdict(Counter)
    for result in results:
        by_suite[cases_by_id[result["case_id"]]["suite"]][result["result"]] += 1
    lines = [
        "# Execution summary",
        "",
        "## Outcome",
        "",
        "`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`",
        "",
        f"The bound run `{manifest['run_id']}` produced 57 schema-valid, hash-bound "
        f"case results: {manifest['result_counts'].get('PASS', 0)} `PASS`, "
        f"{manifest['result_counts'].get('FAIL', 0)} `FAIL`, and "
        f"{manifest['result_counts'].get('BLOCKED_BY_ACCESS', 0)} "
        "`BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or "
        "`NOT_IMPLEMENTED`.",
        "",
        "One low-severity exact-SDK interoperability finding was validated in "
        "`SA-015`. It is not evidence of an authorization bypass in a particular "
        "host. A fixture `PASS` proves only the recorded synthetic subject and "
        "controls.",
        "",
        f"The new closure epoch `{closure['epoch_id']}` passed its own "
        "no-forbidden-mutation gate. Target identities were frozen once with both "
        "optional-lock controls; final checks performed no target inventory and "
        "did not invoke target Git. Historical `SE-001` remains a violation and "
        "is not repaired or reinterpreted.",
        "",
        "## Suite totals",
        "",
        "| Suite | PASS | FAIL | BLOCKED_BY_ACCESS | Total |",
        "|---|---:|---:|---:|---:|",
    ]
    for suite in [
        "Runtime Truth",
        "Stateless Authority",
        "Host Confused Deputy",
        "Local Privilege Containment",
        "OAuth and Browser Identity",
        "Integrated Attack Chain",
    ]:
        counts = by_suite[suite]
        total = counts["PASS"] + counts["FAIL"] + counts["BLOCKED_BY_ACCESS"]
        lines.append(
            f"| {suite} | {counts['PASS']} | {counts['FAIL']} | "
            f"{counts['BLOCKED_BY_ACCESS']} | {total} |"
        )
    lines.extend(
        [
            f"| **Total** | **{manifest['result_counts'].get('PASS', 0)}** | "
            f"**{manifest['result_counts'].get('FAIL', 0)}** | "
            f"**{manifest['result_counts'].get('BLOCKED_BY_ACCESS', 0)}** | "
            "**57** |",
            "",
            "## Containment binding",
            "",
            f"- Qualification: `{qualification['run_id']}` / `{qualification['result']}`.",
            f"- Qualification checks: {len(qualification['checks'])}/12 `PASS`.",
            f"- Browser mode: `{qualification['browser_mode']}`.",
            f"- Qualification digest: `{manifest['qualification_digest']}`.",
            f"- Fixture digest: `{manifest['fixture_digest']}`.",
            f"- Closure epoch: `{closure['epoch_id']}` / `{closure['result']}`.",
            f"- Closure digest: `{manifest['closure_epoch_digest']}`.",
            f"- Final cleanup: `{manifest['cleanup_result']}`.",
            "",
            "## Evidence boundary",
            "",
            "- Browser-required cases blocked because the disposable browser launcher "
            "was not qualified; no normal user browser profile was read.",
            "- The Go SDK case remains blocked because no exact official Go SDK exists "
            "in bounded local caches.",
            "- Exact Python and TypeScript SDK parsers executed from the qualified "
            "cached image with network disabled.",
            "- `RT-012` executed the fidelity-proven mcp-trust archive; other "
            "isolated-copy cases remained blocked where source ownership was unclear.",
            "- No target repair, content/ref/worktree edit, publication, external "
            "write, disclosure, push, or deploy was performed.",
            "- `SE-001` remains the historical Gate 7 violation. The new epoch's "
            "passing gate is separate evidence and does not repair it.",
            "",
        ]
    )
    return "\n".join(lines)


def validated_findings(results: list[dict[str, Any]]) -> list[dict[str, Any]]:
    by_id = {result["case_id"]: result for result in results}
    result = by_id["SA-015"]
    if result["result"] != "FAIL":
        return []
    observation = result["observations"][0]
    finding = {
        "finding_id": "MHAI-SA-015-001",
        "title": "Official Python and TypeScript SDKs diverge on a conflicting request envelope",
        "severity": "LOW",
        "case_ids": ["SA-015"],
        "scope": "Exact cached official SDK request-dispatch parsers in the qualified container.",
        "component": "Python mcp request models and TypeScript MCP SDK request schemas",
        "version": result["subject_version"],
        "coverage_level": "OFFICIAL_SDK",
        "fixture_only": False,
        "trust_boundary": "Untrusted JSON-RPC request envelope to SDK request dispatch.",
        "unauthorized_outcome_or_misleading_claim": (
            "Python accepts and selects params.name='danger' for an envelope carrying "
            "a conflicting top-level name='safe', while TypeScript rejects the same "
            "envelope; cross-SDK execution equivalence is therefore unsafe to assume."
        ),
        "reproduction": [
            "Use the exact qualified cached image with network disabled and a read-only root.",
            "Parse the same JSON-RPC envelope through each SDK's transport and request-dispatch schemas.",
            "Observe Python ACCEPT/tools/call/danger and TypeScript REJECT.",
        ],
        "positive_control": (
            "A synthetic accept-versus-reject pair is detected as a disagreement."
        ),
        "negative_control": (
            "Both exact SDKs accept the valid tools/call control with tool name safe."
        ),
        "evidence": [
            {
                "run_id": result["run_id"],
                "observation_sha256": next(
                    item["observation_digest"] for item in result["evidence"]
                ),
                "package_versions": observation["package_versions"],
                "disagreements": observation["disagreements"],
                "authority_relevant_disagreement": observation[
                    "authority_relevant_disagreement"
                ],
            }
        ],
        "limitations": [
            "No downstream host authorization bypass was demonstrated.",
            "The finding covers only the exact versions and request-dispatch paths recorded.",
            "The two language SDKs have independent release version sequences.",
        ],
        "alternative_explanations": [
            "A downstream Python host may add its own strict unknown-field rejection.",
            "The TypeScript SDK's stricter envelope policy may be intentional.",
        ],
        "independent_confirmation": "NOT_REQUIRED",
    }
    validate(finding, load_json(ROOT / "schemas/finding.schema.json"))
    return [finding]


def render_findings_markdown(
    manifest: dict[str, Any],
    findings: list[dict[str, Any]],
) -> str:
    lines = ["# Findings", ""]
    if not findings:
        lines.extend(
            [
                f"The complete bound run `{manifest['run_id']}` produced no validated finding.",
                "",
            ]
        )
        return "\n".join(lines)
    finding = findings[0]
    lines.extend(
        [
            f"The complete bound run `{manifest['run_id']}` validated one "
            "evidence-bounded finding.",
            "",
            f"## {finding['finding_id']} — {finding['title']}",
            "",
            f"- Severity: `{finding['severity']}`",
            f"- Coverage: `{finding['coverage_level']}`",
            f"- Version: `{finding['version']}`",
            f"- Trust boundary: {finding['trust_boundary']}",
            "",
            finding["unauthorized_outcome_or_misleading_claim"],
            "",
            "This does not establish an authorization bypass in a downstream host. "
            "The machine-readable finding, controls, evidence, limitations, and "
            "alternative explanations are in `results/findings.json`.",
            "",
        ]
    )
    return "\n".join(lines)


def render_coverage(
    manifest: dict[str, Any],
    cases: list[dict[str, Any]],
    results: list[dict[str, Any]],
) -> str:
    cases_by_id = {case["case_id"]: case for case in cases}
    lines = [
        "# Execution coverage",
        "",
        f"Actual results for immutable run `{manifest['run_id']}`. The generated "
        "`COVERAGE-MATRIX.md` remains the pre-execution catalog contract; this file "
        "is the result overlay.",
        "",
        "| Case | Suite | Evidence ceiling | Result | Controls | Containment | Cleanup | Evidence limit or block |",
        "|---|---|---|---|---|---|---|---|",
    ]
    for result in results:
        case = cases_by_id[result["case_id"]]
        controls = (
            f"+{result['control_results']['positive']} "
            f"/ -{result['control_results']['negative']}"
        )
        if result["blocked_reason"] is not None:
            limit = result["blocked_reason"]["detail"]
        elif result["coverage_level"].startswith("FIXTURE_"):
            limit = "Synthetic subject only; no installed-target inference."
        elif result["coverage_level"] == "STATIC_EVIDENCE_ONLY":
            limit = "Static contract evidence only; no live isolation inference."
        else:
            limit = result["limitations"][-1]
        lines.append(
            f"| [{result['case_id']}](results/runs/{manifest['run_id']}/cases/"
            f"{result['case_id']}.json) | {markdown_cell(case['suite'])} | "
            f"{result['coverage_level']} | {result['result']} | {controls} | "
            f"{result['containment_result']} | {result['cleanup_result']} | "
            f"{markdown_cell(limit)} |"
        )
    lines.append("")
    return "\n".join(lines)


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")

    manifest, qualification, closure, cases, results = read_and_validate()
    findings = validated_findings(results)
    outputs = {
        ROOT / "EXECUTION-SUMMARY.md": render_summary(
            manifest, qualification, closure, cases, results
        ),
        ROOT / "EXECUTION-COVERAGE.md": render_coverage(manifest, cases, results),
        ROOT / "FINDINGS.md": render_findings_markdown(manifest, findings),
        ROOT / "results/findings.json": canonical_json(findings),
    }
    mismatches: list[str] = []
    for path, expected in outputs.items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
        elif not path.exists() or path.read_text(encoding="utf-8") != expected:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        print("execution evidence differs: " + ", ".join(mismatches))
        return 1
    print(
        f"{'wrote' if args.write else 'verified'} execution evidence for "
        f"{manifest['run_id']}"
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
