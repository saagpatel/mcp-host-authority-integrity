from __future__ import annotations

import json
import subprocess
import sys
import unittest
from collections import Counter
from pathlib import Path

from harness.schema_validation import (
    SchemaValidationError,
    canonical_digest,
    load_json,
    validate,
    validate_case_contract,
    validate_result_contract,
)

ROOT = Path(__file__).resolve().parents[2]


class CatalogTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = load_json(ROOT / "cases.json")
        cls.schema = load_json(ROOT / "schemas" / "test-case.schema.json")

    def test_exact_case_inventory(self) -> None:
        self.assertEqual(len(self.cases), 57)
        self.assertEqual(len({case["case_id"] for case in self.cases}), 57)
        self.assertEqual(
            Counter(case["case_id"].split("-")[0] for case in self.cases),
            {"RT": 12, "SA": 15, "HC": 12, "LP": 11, "OA": 6, "CHAIN": 1},
        )

    def test_every_case_validates(self) -> None:
        for case in self.cases:
            with self.subTest(case_id=case["case_id"]):
                validate_case_contract(case, self.schema)

    def test_declaration_results_are_immutable_sentinels(self) -> None:
        self.assertTrue(all(case["result"] == "NOT_RUN" for case in self.cases))
        self.assertTrue(all(case["evidence"] == [] for case in self.cases))

    def test_browser_dependency_routing_is_explicit(self) -> None:
        browser_cases = {case["case_id"] for case in self.cases if case["requires_browser"]}
        self.assertEqual(
            browser_cases,
            {"HC-001", "HC-005", "HC-006", "HC-009", "HC-011", "OA-004", "OA-005", "OA-006"},
        )

    def test_source_ids_resolve(self) -> None:
        registry = load_json(ROOT / "sources" / "source-registry.json")
        validate(registry, load_json(ROOT / "schemas" / "source-registry.schema.json"))
        self.assertEqual(registry["sources_digest"], canonical_digest(registry["sources"]))
        source_ids = {source["source_id"] for source in registry["sources"]}
        self.assertEqual(len(source_ids), len(registry["sources"]))
        for case in self.cases:
            with self.subTest(case_id=case["case_id"]):
                self.assertLessEqual(set(case["source_citations"]), source_ids)

    def result_for(self, case: dict, result: str = "PASS") -> dict:
        return {
            "case_id": case["case_id"],
            "run_id": "unit-run",
            "case_definition_digest": canonical_digest(case),
            "oracle_version": "MHAI-ORACLE-1",
            "subject": case["exact_subject_claim"],
            "subject_version": f"fixture:unit@sha256:{'0' * 64}",
            "coverage_level": case["coverage_level"],
            "protocol_status": case["protocol_status"],
            "started_at": "2026-07-19T00:00:00Z",
            "finished_at": "2026-07-19T00:00:01Z",
            "observations": [{"kind": "canary", "value": "safe"}],
            "target_verdict": result,
            "control_results": {"positive": "PASS", "negative": "PASS"},
            "containment_result": "PASS",
            "cleanup_result": "PASS",
            "contradictions": [],
            "result": result,
            "evidence": [{"kind": "unit", "digest": "synthetic"}],
            "limitations": ["unit fixture only"],
            "blocked_reason": None,
        }

    def test_valid_result_binds_to_case_and_precedence(self) -> None:
        result = self.result_for(self.cases[0])
        validate_result_contract(
            result,
            load_json(ROOT / "schemas" / "result.schema.json"),
            self.cases[0],
        )

    def test_pass_cannot_hide_failed_control_or_contradiction(self) -> None:
        schema = load_json(ROOT / "schemas" / "result.schema.json")
        for mutation in (
            ("control_results", {"positive": "FAIL", "negative": "PASS"}),
            ("contradictions", ["descriptor and runtime disagree"]),
            ("target_verdict", "UNKNOWN"),
            ("cleanup_result", "FAIL"),
        ):
            result = self.result_for(self.cases[0])
            result[mutation[0]] = mutation[1]
            with self.subTest(field=mutation[0]), self.assertRaises(SchemaValidationError):
                validate_result_contract(result, schema, self.cases[0])

    def test_subject_version_and_timestamp_are_enforced(self) -> None:
        schema = load_json(ROOT / "schemas" / "result.schema.json")
        for key, value in (
            ("subject_version", ""),
            ("subject_version", "fixture-v1"),
            ("finished_at", "2026-07-18T23:59:59Z"),
            ("started_at", "not-a-timestamp"),
            ("started_at", "2026-07-19T00:00:00"),
        ):
            result = self.result_for(self.cases[0])
            result[key] = value
            with self.subTest(key=key, value=value), self.assertRaises(SchemaValidationError):
                validate_result_contract(result, schema, self.cases[0])

    def test_missing_control_is_representable_as_error(self) -> None:
        schema = load_json(ROOT / "schemas" / "result.schema.json")
        result = self.result_for(self.cases[0], result="ERROR")
        result["target_verdict"] = "UNKNOWN"
        result["control_results"]["positive"] = "NOT_RUN"
        validate_result_contract(result, schema, self.cases[0])

    def test_result_cannot_escalate_evidence_or_change_case_binding(self) -> None:
        schema = load_json(ROOT / "schemas" / "result.schema.json")
        for key, value in (
            ("coverage_level", "LIVE_TARGET"),
            ("protocol_status", "FINAL_PROPOSAL"),
            ("subject", "a different subject claim"),
            ("case_definition_digest", "0" * 64),
        ):
            result = self.result_for(self.cases[0])
            result[key] = value
            with self.subTest(key=key), self.assertRaises(SchemaValidationError):
                validate_result_contract(result, schema, self.cases[0])

    def test_finding_severity_requires_real_evidence_and_review(self) -> None:
        schema = load_json(ROOT / "schemas" / "finding.schema.json")
        finding = {
            "finding_id": "F-001",
            "title": "Fixture-only authority mismatch",
            "severity": "MEDIUM",
            "case_ids": ["RT-001"],
            "scope": "fixture host",
            "component": "synthetic fixture",
            "version": "fixture-v1",
            "coverage_level": "FIXTURE_HOST",
            "fixture_only": True,
            "trust_boundary": "descriptor to retrieved content",
            "unauthorized_outcome_or_misleading_claim": "The fixture reproduced a mismatch.",
            "reproduction": ["Run the synthetic case."],
            "positive_control": "Vulnerable control was detected.",
            "negative_control": "Safe control remained safe.",
            "evidence": [{"kind": "synthetic"}],
            "limitations": ["Not a third-party product claim."],
            "alternative_explanations": ["Fixture behavior only."],
            "independent_confirmation": "NOT_REQUIRED",
        }
        validate(finding, schema)
        for severity in ("HIGH", "CRITICAL"):
            escalated = dict(finding)
            escalated["severity"] = severity
            with self.subTest(severity=severity), self.assertRaises(SchemaValidationError):
                validate(escalated, schema)

    def test_generated_outputs_are_current(self) -> None:
        completed = subprocess.run(
            [sys.executable, "scripts/generate_cases.py", "--check"],
            cwd=ROOT,
            check=False,
            capture_output=True,
            text=True,
        )
        self.assertEqual(completed.returncode, 0, completed.stdout + completed.stderr)

    def test_validator_rejects_extra_key(self) -> None:
        invalid = dict(self.cases[0])
        invalid["undeclared"] = True
        with self.assertRaises(SchemaValidationError):
            validate(invalid, self.schema)

    def test_validator_rejects_bad_id_and_result(self) -> None:
        for key, value in (("case_id", "RT-9999"), ("result", "PASS")):
            invalid = dict(self.cases[0])
            invalid[key] = value
            with self.subTest(key=key), self.assertRaises(SchemaValidationError):
                validate(invalid, self.schema)


if __name__ == "__main__":
    unittest.main()
