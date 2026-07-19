from __future__ import annotations

import json
from typing import Any

from harness.schema_validation import canonical_digest


def synthetic_closure_epoch() -> dict[str, Any]:
    targets = [
        ("mcp-trust", ["RT-012"], "1" * 40, "UNCLEAR"),
        ("PortfolioCommandCenter", ["HC-011", "HC-012"], "2" * 40, "UNCLEAR"),
        ("AIGCCore", ["LP-007"], "3" * 40, "UNCLEAR"),
        ("portfolio-index", ["LP-009"], "4" * 40, "ACTIVE"),
    ]
    return {
        "closure_version": "MHAI-CLOSURE-EPOCH-2",
        "phase": "OPEN",
        "epoch_id": "closure-unit-test",
        "opened_at": "2026-07-19T00:00:00Z",
        "program_commit": "0" * 40,
        "git_read_contract": {
            "environment": "GIT_OPTIONAL_LOCKS=0",
            "argument": "git --no-optional-locks",
        },
        "target_observations": [
            {
                "name": name,
                "case_ids": case_ids,
                "head": head,
                "tree": head,
                "branch": "unit",
                "clean": True,
                "status_sha256": "0" * 64,
                "ownership": ownership,
                "ownership_basis": "synthetic unit-test ownership evidence",
                "metadata": {"unit": True},
                "read_mutation_free": True,
                "archive": {
                    "created": False,
                    "fidelity_proven": False,
                    "reason": "unit test does not execute a target archive",
                },
            }
            for name, case_ids, head, ownership in targets
        ],
        "lane_discovery": {
            "browser": {"eligible": False},
            "go_sdk": {"eligible": False},
            "cross_sdk": {"eligible": True},
            "type_checker": {"eligible": True},
        },
        "historical_exceptions": ["SE-001", "SE-002"],
        "historical_exception_repaired": False,
    }


def closure_context_fields() -> dict[str, str]:
    receipt = synthetic_closure_epoch()
    return {
        "closure_epoch_id": receipt["epoch_id"],
        "closure_epoch_digest": canonical_digest(receipt),
        "closure_epoch_receipt_json": json.dumps(
            receipt,
            sort_keys=True,
            separators=(",", ":"),
        ),
    }
