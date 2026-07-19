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


def qualified_receipt() -> dict:
    value = receipt()
    value["browser_mode"] = "QUALIFIED"
    value["checks"][-1]["observations"] = [
        {
            "browser_launcher_qualified": True,
            "browser_identity": {"contract_version": "MHAI-BROWSER-1"},
            "marker_round_trip_detected": True,
            "fresh_profile_marker_absent": True,
            "profile_symlink_rejected": True,
            "profile_hardlink_rejected": True,
            "normal_profiles_not_read": True,
            "normal_profiles_not_mounted": True,
            "normal_profiles_not_named_in_child_command_or_environment": True,
            "network_denied": True,
            "filesystem_boundary_passed": True,
            "permission_grants_absent": True,
            "device_authority_absent": True,
            "clipboard_authority_absent": True,
            "accounts_sync_extensions_password_store_disabled": True,
            "profile_cleanup_verified": True,
            "watchdog_cleanup_verified": True,
            "controller_death_cleanup_verified": True,
        }
    ]
    return value


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

    def test_qualified_browser_requires_every_containment_control(self) -> None:
        validate_qualification_contract(qualified_receipt())
        invalid = qualified_receipt()
        invalid["checks"][-1]["observations"][0]["network_denied"] = False
        with self.assertRaises(SchemaValidationError):
            validate_qualification_contract(invalid)

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
