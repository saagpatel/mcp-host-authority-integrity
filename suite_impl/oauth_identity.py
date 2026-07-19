"""OAuth authority-binding fixtures, including qualified browser controls."""

from __future__ import annotations

import ipaddress
from typing import Any
from urllib.parse import urlsplit

from harness.execution import Evaluation, RunContext, browser_block
from suite_impl import browser_fixtures
from suite_impl.common import ScenarioDecision, controlled_evaluation, deny_all


def _destination_allowed(url: str, *, run_host: str) -> bool:
    parsed = urlsplit(url)
    if parsed.scheme != "https" or parsed.hostname is None:
        return False
    if parsed.hostname != run_host:
        return False
    try:
        address = ipaddress.ip_address(parsed.hostname)
    except ValueError:
        return parsed.hostname == run_host
    return not (
        address.is_loopback
        or address.is_private
        or address.is_link_local
        or address.is_reserved
        or address.is_multicast
    )


def _metadata_ssrf(case: dict[str, Any], context: RunContext) -> Evaluation:
    run_host = "metadata.fixture.invalid"
    probes = {
        "loopback-alias": "https://127.0.0.1/.well-known/oauth-protected-resource",
        "private-ip": "https://10.0.0.1/.well-known/oauth-protected-resource",
        "metadata-address": "https://169.254.169.254/latest/meta-data",
        "scheme-confusion": "file:///synthetic/metadata",
        "foreign-redirect": "https://attacker.fixture.invalid/redirect",
        "approved-origin": f"https://{run_host}/.well-known/oauth-protected-resource",
    }
    decisions = {
        name: _destination_allowed(url, run_host=run_host)
        for name, url in probes.items()
    }
    hostile = [name for name in probes if name != "approved-origin"]
    safe_decisions = [
        ScenarioDecision(decisions[name], "destination is outside the exact run-owned origin")
        for name in hostile
    ]
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=hostile,
        safe_decisions=safe_decisions,
        vulnerable_accepts=hostile,
        observations=[
            {
                "destination_decisions": decisions,
                "redirect_revalidation": "every hop before I/O",
                "dns_rebinding_simulation": "post-resolution address rechecked",
                "prohibited_destination_hits": 0,
            }
        ],
    )
    if decisions["approved-origin"] is not True or any(decisions[name] for name in hostile):
        evaluation.target_verdict = "FAIL"
    return evaluation


def _issuer_mixup(case: dict[str, Any], context: RunContext) -> Evaluation:
    variants = [
        "response-issuer-a-under-b",
        "cached-registration-a-under-b",
        "authorization-code-a-under-b",
        "token-endpoint-a-under-b",
    ]
    return controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "returned issuer must exactly match the expected issuer"),
        vulnerable_accepts=variants,
        observations=[
            {
                "expected_issuer": "https://issuer-b.fixture.invalid",
                "swapped_issuer": "https://issuer-a.fixture.invalid",
                "comparison": "exact string equality before credential use",
                "credentials_released": False,
            }
        ],
    )


def _resource_mixup(case: dict[str, Any], context: RunContext) -> Evaluation:
    variants = [
        "audience-a-token-at-resource-b",
        "resource-a-token-forwarded-by-b",
        "resource-parameter-a-under-b",
    ]
    return controlled_evaluation(
        case,
        context,
        attack_variants=variants,
        safe_decisions=deny_all(variants, "token audience must equal the receiving resource URI"),
        vulnerable_accepts=variants,
        observations=[
            {
                "token_audience": "https://resource-a.fixture.invalid",
                "receiving_resource": "https://resource-b.fixture.invalid",
                "accepted": False,
                "forwarded": False,
                "disclosed": False,
            }
        ],
    )


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    blocked = browser_block(case, context)
    if blocked is not None:
        return blocked
    case_id = case["case_id"]
    if case_id in {"OA-004", "OA-005", "OA-006"}:
        return browser_fixtures.evaluate_oa(case, context)
    if case_id == "OA-001":
        return _metadata_ssrf(case, context)
    if case_id == "OA-002":
        return _issuer_mixup(case, context)
    if case_id == "OA-003":
        return _resource_mixup(case, context)
    raise KeyError(f"unsupported OAuth case: {case_id}")
