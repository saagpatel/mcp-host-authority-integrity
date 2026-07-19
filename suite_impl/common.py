"""Shared deterministic control runner for synthetic fixture cases."""

from __future__ import annotations

import secrets
from dataclasses import dataclass
from typing import Any

from harness.canary_store import CanaryStore
from harness.effect_broker import EffectBroker
from harness.execution import Evaluation, RunContext


@dataclass(frozen=True)
class ScenarioDecision:
    accepted: bool
    reason: str


def controlled_evaluation(
    case: dict[str, Any],
    context: RunContext,
    *,
    attack_variants: list[str],
    safe_decisions: list[ScenarioDecision],
    vulnerable_accepts: list[str],
    observations: list[dict[str, Any]] | None = None,
    limitations: list[str] | None = None,
) -> Evaluation:
    """Exercise a real canary sensor around explicit safe and vulnerable models."""
    expected_variants = set(attack_variants)
    safe_by_variant = {
        variant: decision
        for variant, decision in zip(attack_variants, safe_decisions, strict=False)
    }
    if len(safe_decisions) != len(attack_variants) or set(safe_by_variant) != expected_variants:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[{"control_error": "safe decision matrix is incomplete"}],
            positive_control="FAIL",
            negative_control="FAIL",
            limitations=limitations or [],
        )
    if set(vulnerable_accepts) != expected_variants:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[{"control_error": "vulnerable decision matrix is incomplete"}],
            positive_control="FAIL",
            negative_control="FAIL",
            limitations=limitations or [],
        )

    canaries = CanaryStore(
        context.case_root / "canaries",
        f"{context.run_id}-{case['case_id'].lower()}",
        secrets.token_hex(16),
    )
    broker = EffectBroker(canaries)
    try:
        vulnerable_effect = broker.write_canary(
            "positive-control.json",
            {
                "case_id": case["case_id"],
                "accepted_variants": sorted(vulnerable_accepts),
            },
            allowed=bool(vulnerable_accepts),
        )
        safe_accepts = sorted(
            variant for variant, decision in safe_by_variant.items() if decision.accepted
        )
        safe_effect = broker.write_canary(
            "safe-subject.json",
            {
                "case_id": case["case_id"],
                "accepted_variants": safe_accepts,
            },
            allowed=bool(safe_accepts),
        )
        positive_ok = vulnerable_effect and canaries.read("positive-control.json")["value"][
            "accepted_variants"
        ] == sorted(vulnerable_accepts)
        negative_ok = not safe_effect and canaries.absent("safe-subject.json")
        decision_rows = [
            {
                "variant": variant,
                "accepted": decision.accepted,
                "reason": decision.reason,
            }
            for variant, decision in safe_by_variant.items()
        ]
        return Evaluation(
            target_verdict="PASS" if positive_ok and negative_ok else "FAIL",
            observations=[
                {
                    "case_id": case["case_id"],
                    "attack_variants": attack_variants,
                    "safe_decisions": decision_rows,
                    "vulnerable_control_accepted": sorted(vulnerable_accepts),
                    "positive_canary_detected": positive_ok,
                    "safe_canary_absent": negative_ok,
                    "broker_attempts": broker.attempts,
                },
                *(observations or []),
            ],
            limitations=limitations or [],
            positive_control="PASS" if positive_ok else "FAIL",
            negative_control="PASS" if negative_ok else "FAIL",
        )
    finally:
        canaries.close()


def deny_all(variants: list[str], reason: str) -> list[ScenarioDecision]:
    return [ScenarioDecision(False, reason) for _ in variants]
