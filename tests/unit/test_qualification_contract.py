from __future__ import annotations

import unittest

from harness.qualification import (
    aggregate_qualification_result,
    validate_qualification_contract,
)
from harness.schema_validation import SchemaValidationError


def receipt() -> dict:
    return {
        "qualification_version": "MHAI-CONTAINMENT-1",
        "run_id": "qualification-unit",
        "harness_digest": "0" * 64,
        "runtime": {
            "os": "unit",
            "python": "unit",
            "container_server": "unit",
            "container_image": "sha256:" + ("0" * 64),
        },
        "started_at": "2026-07-19T00:00:00Z",
        "finished_at": "2026-07-19T00:00:01Z",
        "checks": [
            {
                "check_id": f"CQ-{index:03d}",
                "result": "PASS",
                "observations": (
                    [{"all_browser_cases_refused": True}] if index == 12 else [{"unit": True}]
                ),
            }
            for index in range(1, 13)
        ],
        "browser_mode": "BROWSER_DISABLED",
        "result": "PASS",
        "limitations": ["unit"],
    }


class QualificationContractTests(unittest.TestCase):
    def test_valid_exact_contract(self) -> None:
        validate_qualification_contract(receipt())

    def test_overall_pass_cannot_hide_failed_check(self) -> None:
        invalid = receipt()
        invalid["checks"][3]["result"] = "FAIL"
        with self.assertRaises(SchemaValidationError):
            validate_qualification_contract(invalid)

    def test_duplicate_or_missing_identity_is_rejected(self) -> None:
        invalid = receipt()
        invalid["checks"][4]["check_id"] = "CQ-004"
        with self.assertRaises(SchemaValidationError):
            validate_qualification_contract(invalid)

    def test_browser_disabled_requires_exercised_refusal(self) -> None:
        invalid = receipt()
        invalid["checks"][-1]["observations"] = [{"browser_cases_must_block": True}]
        with self.assertRaises(SchemaValidationError):
            validate_qualification_contract(invalid)

    def test_qualified_browser_mode_requires_a_new_active_launcher(self) -> None:
        invalid = receipt()
        invalid["browser_mode"] = "QUALIFIED"
        with self.assertRaises(SchemaValidationError):
            validate_qualification_contract(invalid)

    def test_qualified_browser_mode_accepts_repeatable_isolated_launcher(self) -> None:
        valid = receipt()
        valid["browser_mode"] = "QUALIFIED"
        valid["checks"][-1]["observations"] = [
            {
                "repeatable_launcher_qualified": True,
                "normal_profiles_read": False,
                "normal_profiles_mounted": False,
            }
        ]
        validate_qualification_contract(valid)

    def test_all_pass_cannot_publish_pass_without_verified_cleanup(self) -> None:
        self.assertEqual(
            aggregate_qualification_result(
                receipt()["checks"],
                cleanup_verified=False,
            ),
            "ERROR",
        )


if __name__ == "__main__":
    unittest.main()
