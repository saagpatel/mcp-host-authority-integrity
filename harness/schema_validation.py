"""Small, deterministic validator for the JSON Schema subset used by MHAI."""

from __future__ import annotations

import hashlib
import json
import re
from datetime import datetime
from pathlib import Path
from typing import Any


class SchemaValidationError(ValueError):
    """Raised when an instance does not satisfy a program schema."""


TYPE_MAP = {
    "object": dict,
    "array": list,
    "string": str,
    "integer": int,
    "null": type(None),
    "boolean": bool,
}


def load_json(path: Path) -> Any:
    with path.open("r", encoding="utf-8") as handle:
        return json.load(handle)


def validate(instance: Any, schema: dict[str, Any], path: str = "$") -> None:
    """Validate the deliberately small schema vocabulary used by this program."""
    for subschema in schema.get("allOf", []):
        validate(instance, subschema, path)
    if "if" in schema:
        try:
            validate(instance, schema["if"], path)
        except SchemaValidationError:
            if "else" in schema:
                validate(instance, schema["else"], path)
        else:
            if "then" in schema:
                validate(instance, schema["then"], path)
    if "anyOf" in schema:
        errors: list[str] = []
        for option in schema["anyOf"]:
            try:
                validate(instance, option, path)
                break
            except SchemaValidationError as exc:
                errors.append(str(exc))
        else:
            raise SchemaValidationError(f"{path}: no anyOf option matched; {errors}")
    if "oneOf" in schema:
        successes = 0
        errors: list[str] = []
        for option in schema["oneOf"]:
            try:
                validate(instance, option, path)
                successes += 1
            except SchemaValidationError as exc:
                errors.append(str(exc))
        if successes != 1:
            raise SchemaValidationError(
                f"{path}: expected exactly one oneOf match, got {successes}; {errors}"
            )
        return

    expected_type = schema.get("type")
    if expected_type is not None:
        expected = TYPE_MAP[expected_type]
        if expected_type == "integer":
            valid_type = isinstance(instance, int) and not isinstance(instance, bool)
        else:
            valid_type = isinstance(instance, expected)
        if not valid_type:
            raise SchemaValidationError(
                f"{path}: expected {expected_type}, got {type(instance).__name__}"
            )

    if "const" in schema and instance != schema["const"]:
        raise SchemaValidationError(f"{path}: expected constant {schema['const']!r}")
    if "enum" in schema and instance not in schema["enum"]:
        raise SchemaValidationError(f"{path}: value {instance!r} is outside enum")
    if isinstance(instance, str):
        if len(instance) < schema.get("minLength", 0):
            raise SchemaValidationError(f"{path}: string is shorter than minLength")
        pattern = schema.get("pattern")
        if pattern is not None and re.fullmatch(pattern, instance) is None:
            raise SchemaValidationError(f"{path}: value does not match {pattern!r}")
    if isinstance(instance, int) and not isinstance(instance, bool):
        if "minimum" in schema and instance < schema["minimum"]:
            raise SchemaValidationError(f"{path}: value is below minimum")
        if "maximum" in schema and instance > schema["maximum"]:
            raise SchemaValidationError(f"{path}: value is above maximum")
    if isinstance(instance, list):
        if len(instance) < schema.get("minItems", 0):
            raise SchemaValidationError(f"{path}: array is shorter than minItems")
        if "maxItems" in schema and len(instance) > schema["maxItems"]:
            raise SchemaValidationError(f"{path}: array is longer than maxItems")
        item_schema = schema.get("items")
        if item_schema is not None:
            for index, item in enumerate(instance):
                validate(item, item_schema, f"{path}[{index}]")
    if isinstance(instance, dict):
        required = schema.get("required", [])
        missing = sorted(set(required) - set(instance))
        if missing:
            raise SchemaValidationError(f"{path}: missing required keys {missing}")
        properties = schema.get("properties", {})
        if schema.get("additionalProperties") is False:
            extras = sorted(set(instance) - set(properties))
            if extras:
                raise SchemaValidationError(f"{path}: unexpected keys {extras}")
        for key, value in instance.items():
            if key in properties:
                validate(value, properties[key], f"{path}.{key}")


def validate_file(instance_path: Path, schema_path: Path) -> None:
    validate(load_json(instance_path), load_json(schema_path))


def canonical_digest(value: Any) -> str:
    encoded = json.dumps(value, sort_keys=True, separators=(",", ":"), ensure_ascii=True)
    return hashlib.sha256(encoded.encode("utf-8")).hexdigest()


def validate_case_contract(case: dict[str, Any], schema: dict[str, Any]) -> None:
    validate(case, schema)
    if case["coverage_level"] != case["evidence_ceiling"]["coverage_level"]:
        raise SchemaValidationError(
            "$.evidence_ceiling.coverage_level: must equal $.coverage_level"
        )
    if case["exact_subject_claim"] != case["evidence_ceiling"]["subject"]:
        raise SchemaValidationError(
            "$.evidence_ceiling.subject: must equal $.exact_subject_claim"
        )
    try:
        re.compile(case["evidence_ceiling"]["version_pattern"])
    except re.error as exc:
        raise SchemaValidationError(
            f"$.evidence_ceiling.version_pattern: invalid regular expression: {exc}"
        ) from exc


def expected_result(result: dict[str, Any]) -> str:
    controls = result["control_results"]
    if (
        "FAIL" in controls.values()
        or result["containment_result"] == "FAIL"
        or result["cleanup_result"] == "FAIL"
    ):
        return "ERROR"
    if result["target_verdict"] == "BLOCKED":
        reason = result["blocked_reason"]
        if not isinstance(reason, dict):
            return "ERROR"
        return "BLOCKED_BY_AUTHORITY" if reason["kind"] == "AUTHORITY" else "BLOCKED_BY_ACCESS"
    if result["result"] in {"NOT_IMPLEMENTED", "NOT_RUN"}:
        return result["result"]
    if "NOT_RUN" in controls.values():
        return "ERROR"
    if result["containment_result"] == "NOT_RUN" or result["cleanup_result"] == "NOT_RUN":
        return "ERROR"
    if result["contradictions"]:
        return "UNKNOWN"
    if result["target_verdict"] == "FAIL":
        return "FAIL"
    if result["target_verdict"] == "PASS":
        return "PASS"
    return "UNKNOWN"


def validate_result_contract(
    result: dict[str, Any],
    result_schema: dict[str, Any],
    case: dict[str, Any],
) -> None:
    validate(result, result_schema)
    expected_bindings = {
        "case_id": case["case_id"],
        "case_definition_digest": canonical_digest(case),
        "subject": case["exact_subject_claim"],
        "coverage_level": case["evidence_ceiling"]["coverage_level"],
        "protocol_status": case["protocol_status"],
    }
    for key, expected in expected_bindings.items():
        if result[key] != expected:
            raise SchemaValidationError(
                f"$.{key}: result binding {result[key]!r} does not equal case {expected!r}"
            )
    version_required = result["result"] not in {
        "ERROR",
        "NOT_IMPLEMENTED",
        "NOT_RUN",
    }
    if (
        version_required
        and re.fullmatch(
            case["evidence_ceiling"]["version_pattern"],
            result["subject_version"],
        )
        is None
    ):
        raise SchemaValidationError(
            "$.subject_version: does not satisfy the case evidence-ceiling version_pattern"
        )
    try:
        started = datetime.fromisoformat(result["started_at"].replace("Z", "+00:00"))
        finished = datetime.fromisoformat(result["finished_at"].replace("Z", "+00:00"))
    except ValueError as exc:
        raise SchemaValidationError(f"$.started_at/finished_at: invalid timestamp: {exc}") from exc
    if started.utcoffset() is None or finished.utcoffset() is None:
        raise SchemaValidationError("$.started_at/finished_at: timezone offset is required")
    if finished < started:
        raise SchemaValidationError("$.finished_at: must not precede $.started_at")
    derived = expected_result(result)
    if result["result"] != derived:
        raise SchemaValidationError(
            f"$.result: declared {result['result']!r}, deterministic contract derives {derived!r}"
        )
