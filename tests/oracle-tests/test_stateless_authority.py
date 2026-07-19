from __future__ import annotations

import json
import unittest
from pathlib import Path

from harness.execution import RunContext, deterministic_declared_result
from suite_impl.stateless_authority import evaluate


ROOT = Path(__file__).resolve().parents[2]


def _cases() -> dict[str, dict]:
    values = json.loads(
        (ROOT / "suites" / "stateless-authority" / "cases.json").read_text(
            encoding="utf-8"
        )
    )
    return {
        case["case_id"]: case
        for case in values
        if case["case_id"].startswith("SA-")
    }


def _context() -> RunContext:
    return RunContext(
        run_id="stateless-authority-oracle-test",
        run_root=Path("/synthetic/in-memory-only"),
        browser_mode="BROWSER_DISABLED",
        qualification_digest="0" * 64,
    )


class StatelessAuthorityOracleTests(unittest.TestCase):
    @classmethod
    def setUpClass(cls) -> None:
        cls.cases = _cases()
        cls.context = _context()

    def test_catalog_has_exact_sa_range(self) -> None:
        self.assertEqual(
            sorted(self.cases),
            [f"SA-{index:03d}" for index in range(1, 16)],
        )
        self.assertTrue(all(not case["requires_browser"] for case in self.cases.values()))

    def test_fixture_cases_exercise_fresh_vulnerable_and_safe_controls(self) -> None:
        for index in range(1, 14):
            case_id = f"SA-{index:03d}"
            with self.subTest(case_id=case_id):
                case = self.cases[case_id]
                result = evaluate(case, self.context)
                self.assertEqual(result.target_verdict, "PASS")
                self.assertEqual(result.positive_control, "PASS")
                self.assertEqual(result.negative_control, "PASS")
                self.assertIsNone(result.blocked_kind)
                self.assertFalse(result.contradictions)

                observation = result.observations[0]
                self.assertEqual(observation["pass_oracle"], case["pass_oracle"])
                self.assertEqual(observation["fail_oracle"], case["fail_oracle"])
                self.assertEqual(
                    observation["protocol_status"],
                    case["protocol_status"],
                )
                self.assertTrue(observation["synthetic_only"])
                positive = observation["control_domains"]["positive"]
                negative = observation["control_domains"]["negative"]
                self.assertNotEqual(positive["domain_id"], negative["domain_id"])
                self.assertTrue(positive["deliberately_vulnerable"])
                self.assertTrue(positive["fail_oracle_observed"])
                self.assertTrue(negative["safe_fixture"])
                self.assertTrue(negative["pass_oracle_observed"])

    def test_fixture_evaluations_are_deterministic(self) -> None:
        for index in range(1, 14):
            case_id = f"SA-{index:03d}"
            with self.subTest(case_id=case_id):
                first = evaluate(self.cases[case_id], self.context)
                second = evaluate(self.cases[case_id], self.context)
                self.assertEqual(first, second)

    def test_sa001_rejects_every_named_invalid_authority_class(self) -> None:
        observation = evaluate(self.cases["SA-001"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["rejected_variants"],
            ["cross_principal", "cross_tool", "expired", "neighboring", "revoked"],
        )
        self.assertTrue(facts["uniform_denial"])
        self.assertFalse(facts["disclosure"])

    def test_sa002_rejects_each_mutation_class(self) -> None:
        observation = evaluate(self.cases["SA-002"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["rejected_mutation_classes"],
            ["byte", "casing", "encoding", "field", "wrapper"],
        )
        self.assertTrue(facts["valid_control_accepted"])

    def test_sa003_binds_all_continuation_authority_dimensions(self) -> None:
        observation = evaluate(self.cases["SA-003"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["rejected_swap_classes"],
            [
                "cross_prompt",
                "cross_request",
                "cross_server",
                "cross_tool",
                "cross_user",
            ],
        )
        self.assertTrue(facts["originating_request_accepted"])

    def test_sa004_replay_has_one_stable_outcome_and_effect(self) -> None:
        observation = evaluate(self.cases["SA-004"], self.context).observations[0]
        positive = observation["control_domains"]["positive"]["facts"]
        negative = observation["control_domains"]["negative"]["facts"]
        self.assertGreater(positive["counter"], 1)
        self.assertEqual(negative["counter"], 1)
        self.assertTrue(negative["stable_outcome"])

    def test_sa005_all_task_operations_are_tenant_bound(self) -> None:
        observation = evaluate(self.cases["SA-005"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["denied_operations"],
            ["cancel", "get", "list", "result", "update"],
        )
        self.assertTrue(facts["indistinguishable_denial"])

    def test_sa006_revocation_blocks_result_and_pending_effect(self) -> None:
        observation = evaluate(self.cases["SA-006"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertFalse(facts["retrieved_after_revocation"])
        self.assertEqual(facts["pending_side_effects_completed"], 0)

    def test_sa007_cancellation_reconciles_every_schedule(self) -> None:
        observation = evaluate(self.cases["SA-007"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["reconciled_schedules"],
            ["cancel_at_boundary", "cancel_before_work", "complete_before_cancel"],
        )
        self.assertEqual(facts["post_cancel_canaries"], 0)

    def test_sa008_current_request_capability_wins(self) -> None:
        observation = evaluate(self.cases["SA-008"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(facts["omitting_request_response"], "synchronous")
        self.assertFalse(facts["unadvertised_task_created"])

    def test_sa009_forged_stale_and_missing_parents_release_nothing(self) -> None:
        observation = evaluate(self.cases["SA-009"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["rejected_associations"],
            [
                "elicitation_after_completion",
                "roots_forged_parent",
                "sampling_without_parent",
            ],
        )
        self.assertEqual(facts["released_shapes"], [])
        self.assertTrue(facts["live_parent_control_accepted"])

    def test_sa010_rejects_every_header_body_ambiguity_before_auth(self) -> None:
        observation = evaluate(self.cases["SA-010"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(
            facts["rejected_before_authorization"],
            [
                "case_varied_duplicate_name",
                "duplicate_method",
                "invalid_encoding",
                "method_disagreement",
                "name_disagreement",
                "proxy_normalization",
            ],
        )
        self.assertTrue(facts["valid_control_reached_canary"])

    def test_sa011_cache_hits_only_exact_unexpired_authority_tuple(self) -> None:
        observation = evaluate(self.cases["SA-011"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(facts["changed_dimension_hits"], [])
        self.assertTrue(facts["exact_tuple_hit"])
        self.assertFalse(facts["expired_at_time_101_hit"])

    def test_sa012_self_asserted_metadata_never_changes_policy(self) -> None:
        observation = evaluate(self.cases["SA-012"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(facts["forged_decision"], facts["untrusted_decision"])
        self.assertTrue(facts["same_policy_decision"])

    def test_sa013_rotation_never_restores_principal_operation_budget(self) -> None:
        observation = evaluate(self.cases["SA-013"], self.context).observations[0]
        facts = observation["control_domains"]["negative"]["facts"]
        self.assertEqual(facts["rotations_restoring_budget"], [])
        self.assertTrue(facts["principal_operation_budget_exhausted"])

    def test_official_sdk_cases_block_instead_of_simulating_evidence(self) -> None:
        for case_id in ("SA-014", "SA-015"):
            with self.subTest(case_id=case_id):
                result = evaluate(self.cases[case_id], self.context)
                self.assertEqual(result.target_verdict, "BLOCKED")
                self.assertEqual(result.blocked_kind, "ACCESS")
                self.assertEqual(
                    deterministic_declared_result(result),
                    "BLOCKED_BY_ACCESS",
                )
                self.assertEqual(result.positive_control, "NOT_RUN")
                self.assertEqual(result.negative_control, "NOT_RUN")
                observation = result.observations[0]
                self.assertEqual(observation["coverage_level"], "OFFICIAL_SDK")
                self.assertFalse(observation["exact_official_sdk_available"])
                self.assertTrue(observation["simulated_official_sdk_refused"])
                self.assertFalse(observation["synthetic_positive_control_executed"])
                self.assertFalse(observation["synthetic_negative_control_executed"])

    def test_catalog_oracle_drift_fails_closed(self) -> None:
        drifted = dict(self.cases["SA-001"])
        drifted["pass_oracle"] = "weaker substituted oracle"
        result = evaluate(drifted, self.context)
        self.assertEqual(result.target_verdict, "UNKNOWN")
        self.assertEqual(result.positive_control, "NOT_RUN")
        self.assertEqual(result.negative_control, "NOT_RUN")
        self.assertTrue(result.contradictions)


if __name__ == "__main__":
    unittest.main()
