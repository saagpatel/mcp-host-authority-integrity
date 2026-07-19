from __future__ import annotations

import unittest
from pathlib import Path

from harness.execution import RunContext, deterministic_declared_result
from harness.schema_validation import load_json
from suite_impl.host_confused_deputy import evaluate
from tests.helpers import closure_context_fields

ROOT = Path(__file__).resolve().parents[2]


class HostConfusedDeputyOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cases = load_json(ROOT / "suites" / "host-confused-deputy" / "cases.json")
        cls.cases = {case["case_id"]: case for case in cases}

    def context(self, browser_mode: str = "BROWSER_DISABLED") -> RunContext:
        return RunContext(
            run_id="hc-oracle-unit-run",
            run_root=ROOT / "work" / "unused-hc-oracle-unit-run",
            browser_mode=browser_mode,
            qualification_digest="0" * 64,
            **closure_context_fields(),
        )

    def test_browser_cases_use_fail_closed_policy(self) -> None:
        for case_id in ("HC-001", "HC-005", "HC-006", "HC-009", "HC-011"):
            with self.subTest(case_id=case_id):
                result = evaluate(self.cases[case_id], self.context())
                self.assertEqual(result.target_verdict, "BLOCKED")
                self.assertEqual(result.blocked_kind, "ACCESS")
                self.assertEqual(
                    deterministic_declared_result(result),
                    "BLOCKED_BY_ACCESS",
                )
                self.assertIn("BROWSER_DISABLED", result.blocked_detail or "")
                self.assertEqual(
                    result.observations,
                    [
                        {
                            "browser_required": True,
                            "browser_mode": "BROWSER_DISABLED",
                            "unsafe_fallback_refused": True,
                        }
                    ],
                )

    def test_target_browser_case_still_requires_exact_owned_archive(self) -> None:
        result = evaluate(self.cases["HC-011"], self.context("QUALIFIED"))
        self.assertEqual(deterministic_declared_result(result), "BLOCKED_BY_ACCESS")
        self.assertIn("immutable program-owned archive", result.blocked_detail or "")
        self.assertTrue(result.observations[0]["unsafe_fallback_refused"])
        self.assertFalse(result.observations[0]["target_repository_accessed_during_case"])

    def test_synthetic_cases_have_valid_positive_and_negative_controls(self) -> None:
        for case_id in ("HC-002", "HC-003", "HC-004", "HC-007", "HC-008", "HC-010"):
            with self.subTest(case_id=case_id):
                result = evaluate(self.cases[case_id], self.context())
                self.assertEqual(result.target_verdict, "PASS")
                self.assertEqual(result.positive_control, "PASS")
                self.assertEqual(result.negative_control, "PASS")
                self.assertEqual(result.containment_result, "PASS")
                self.assertEqual(result.cleanup_result, "PASS")
                self.assertEqual(deterministic_declared_result(result), "PASS")
                summary = result.observations[-1]
                self.assertEqual(summary["kind"], "control-summary")
                self.assertTrue(
                    summary["vulnerable_control_reached_forbidden_boundary"]
                )
                self.assertTrue(summary["safe_subject_rejected_attack"])
                self.assertFalse(summary["external_effects_attempted"])

    def test_tool_visibility_and_server_binding_oracles(self) -> None:
        visibility = evaluate(self.cases["HC-002"], self.context()).observations[0]
        self.assertEqual(visibility["safe_app_server_a"], ["render", "shared"])
        self.assertEqual(visibility["safe_model_server_a"], ["shared", "summarize"])
        self.assertEqual(visibility["safe_cross_server_invocation"], "rejected")
        self.assertEqual(visibility["vulnerable_same_name_selected_server"], "server-b")

        binding = evaluate(self.cases["HC-003"], self.context()).observations[0]
        self.assertEqual(binding["vulnerable_sibling_call"], "accepted")
        self.assertEqual(binding["safe_sibling_call"], "rejected")
        self.assertEqual(binding["safe_bound_call"], "accepted")

    def test_template_review_is_bound_to_content_digest(self) -> None:
        observation = evaluate(self.cases["HC-004"], self.context()).observations[0]
        self.assertTrue(observation["uri_stable"])
        self.assertTrue(observation["content_digest_changed"])
        self.assertTrue(observation["vulnerable_reused_prior_review"])
        self.assertFalse(observation["safe_render_after_change_before_review"])
        self.assertTrue(observation["safe_render_after_revalidation"])

    def test_app_context_stays_lower_authority_and_document_scoped(self) -> None:
        observation = evaluate(self.cases["HC-007"], self.context()).observations[0]
        self.assertTrue(observation["vulnerable_host_context_overwritten"])
        self.assertTrue(observation["safe_host_context_preserved"])
        self.assertEqual(observation["safe_app_context_authority"], "untrusted")
        self.assertEqual(observation["safe_document_cleanup_count"], 0)

    def test_unsupported_app_fallback_is_inert(self) -> None:
        observation = evaluate(self.cases["HC-008"], self.context()).observations[0]
        self.assertEqual(observation["vulnerable_mode"], "executed")
        self.assertEqual(observation["vulnerable_sensor_hits"], 1)
        self.assertEqual(observation["safe_mode"], "inert_text")
        self.assertEqual(observation["safe_sensor_hits"], 0)
        self.assertTrue(observation["safe_preserved_text"])

    def test_root_oracle_denies_every_escape_without_filesystem_access(self) -> None:
        observation = evaluate(self.cases["HC-010"], self.context()).observations[0]
        self.assertFalse(any(observation["safe_attack_authorizations"].values()))
        self.assertTrue(any(observation["vulnerable_attack_authorizations"].values()))
        self.assertTrue(observation["safe_legitimate_authorization"])
        self.assertFalse(observation["filesystem_access_performed"])

    def test_hc_012_refuses_unclear_owner_copy(self) -> None:
        result = evaluate(self.cases["HC-012"], self.context())
        self.assertEqual(deterministic_declared_result(result), "BLOCKED_BY_ACCESS")
        self.assertEqual(result.blocked_kind, "ACCESS")
        self.assertIn("ownership is not clear", result.blocked_detail or "")
        self.assertFalse(result.observations[0]["isolated_copy_available"])
        self.assertFalse(result.observations[0]["target_repository_accessed_during_case"])
        self.assertFalse(result.observations[0]["substitute_fixture_claimed"])

    def test_non_hc_case_is_rejected(self) -> None:
        with self.assertRaisesRegex(ValueError, "unsupported Host Confused Deputy"):
            evaluate({"case_id": "RT-001"}, self.context())


if __name__ == "__main__":
    unittest.main()
