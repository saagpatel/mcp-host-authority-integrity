"""One end-to-end synthetic authority chain with transition-level truth."""

from __future__ import annotations

from typing import Any

from harness.execution import Evaluation, RunContext
from suite_impl.common import ScenarioDecision, controlled_evaluation


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    transitions = [
        {
            "transition": "descriptor-to-runtime",
            "safe_result": "STOPPED",
            "defense": "retrieved body classified independently from descriptor",
        },
        {
            "transition": "runtime-to-state",
            "safe_result": "NOT_REACHED",
            "defense": "state handle bound to authority tuple",
        },
        {
            "transition": "state-to-app",
            "safe_result": "NOT_REACHED",
            "defense": "app message bound to server and request",
        },
        {
            "transition": "app-to-local",
            "safe_result": "NOT_REACHED",
            "defense": "local effect requires exact scoped approval",
        },
    ]
    return controlled_evaluation(
        case,
        context,
        attack_variants=["descriptor-runtime-state-app-local-chain"],
        safe_decisions=[
            ScenarioDecision(
                False,
                "first effective defense: retrieved runtime body contradicts the descriptor",
            )
        ],
        vulnerable_accepts=["descriptor-runtime-state-app-local-chain"],
        observations=[
            {
                "safe_chain": transitions,
                "first_effective_defense": "descriptor-to-runtime body classification",
                "downstream_defenses_claimed_passed": False,
                "vulnerable_control_transitions_observed": [
                    "descriptor-to-runtime",
                    "runtime-to-state",
                    "state-to-app",
                    "app-to-local",
                ],
                "vulnerable_control_effect_scope": "program-owned canary only",
            }
        ],
    )
