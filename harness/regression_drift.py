"""Read-only drift classification for the canonical MHAI regression baseline."""

from __future__ import annotations

import argparse
import fnmatch
import json
import re
import subprocess
import sys
import tempfile
from collections.abc import Callable
from datetime import UTC, datetime
from pathlib import Path
from typing import Any
from urllib.error import HTTPError, URLError
from urllib.request import Request, urlopen

from harness.schema_validation import load_json, validate

ROOT = Path(__file__).resolve().parents[1]
BASELINE_PATH = ROOT / "regression-baseline.json"
BASELINE_SCHEMA_PATH = ROOT / "schemas" / "regression-baseline.schema.json"
REPORT_SCHEMA_PATH = ROOT / "schemas" / "drift-report.schema.json"
API_ROOT = "https://api.github.com"


class DriftCheckError(RuntimeError):
    """A read required for drift classification was unavailable or invalid."""


def _require_exact_keys(value: dict[str, Any], expected: set[str], label: str) -> None:
    actual = set(value)
    if actual != expected:
        missing = sorted(expected - actual)
        extra = sorted(actual - expected)
        raise DriftCheckError(f"{label}: missing keys {missing}; unexpected keys {extra}")


def _require_sha(value: Any, label: str) -> None:
    if not isinstance(value, str) or re.fullmatch(r"[0-9a-f]{40}", value) is None:
        raise DriftCheckError(f"{label}: expected a 40-character lowercase Git id")


def _validate_repository_config(
    value: Any,
    *,
    label: str,
    target: bool,
) -> None:
    if not isinstance(value, dict):
        raise DriftCheckError(f"{label}: expected an object")
    expected = {"path", "baseline_commit", "non_material_paths"}
    if target:
        expected |= {"name", "case_ids", "baseline_tree"}
    _require_exact_keys(value, expected, label)
    if not isinstance(value["path"], str) or not Path(value["path"]).is_absolute():
        raise DriftCheckError(f"{label}.path: expected an absolute path")
    _require_sha(value["baseline_commit"], f"{label}.baseline_commit")
    patterns = value["non_material_paths"]
    if (
        not isinstance(patterns, list)
        or any(not isinstance(item, str) or not item for item in patterns)
    ):
        raise DriftCheckError(f"{label}.non_material_paths: invalid patterns")
    if target:
        if not isinstance(value["name"], str) or not value["name"]:
            raise DriftCheckError(f"{label}.name: expected a non-empty string")
        case_ids = value["case_ids"]
        if (
            not isinstance(case_ids, list)
            or not case_ids
            or any(not isinstance(item, str) or not item for item in case_ids)
        ):
            raise DriftCheckError(f"{label}.case_ids: expected non-empty strings")
        _require_sha(value["baseline_tree"], f"{label}.baseline_tree")


def validate_baseline_contract(baseline: Any) -> None:
    if not isinstance(baseline, dict):
        raise DriftCheckError("baseline: expected an object")
    validate(baseline, load_json(BASELINE_SCHEMA_PATH))
    evidence = baseline["canonical_evidence"]
    _require_exact_keys(
        evidence,
        {
            "program_commit",
            "epoch_id",
            "qualification_id",
            "run_id",
            "pass_count",
            "fail_count",
            "blocked_count",
            "preserved_failures",
        },
        "canonical_evidence",
    )
    _require_sha(evidence["program_commit"], "canonical_evidence.program_commit")
    counts = [
        evidence["pass_count"],
        evidence["fail_count"],
        evidence["blocked_count"],
    ]
    if any(not isinstance(item, int) or isinstance(item, bool) or item < 0 for item in counts):
        raise DriftCheckError("canonical_evidence: invalid result counts")
    if sum(counts) != 57:
        raise DriftCheckError("canonical_evidence: result counts must total 57")
    _validate_repository_config(baseline["program"], label="program", target=False)
    if baseline["program"]["baseline_commit"] != evidence["program_commit"]:
        raise DriftCheckError("program baseline commit does not match canonical evidence")
    targets = baseline["targets"]
    if not isinstance(targets, list) or not targets:
        raise DriftCheckError("targets: expected a non-empty array")
    names: list[str] = []
    case_ids: list[str] = []
    for index, target in enumerate(targets):
        _validate_repository_config(target, label=f"targets[{index}]", target=True)
        names.append(target["name"])
        case_ids.extend(target["case_ids"])
    if len(names) != len(set(names)):
        raise DriftCheckError("targets: duplicate target names")
    if len(case_ids) != len(set(case_ids)):
        raise DriftCheckError("targets: duplicate case ids")
    upstream = baseline["upstream"]
    _require_exact_keys(
        upstream,
        {
            "python_sdk",
            "typescript_sdk",
            "protocol_issue",
            "conformance_pull_request",
        },
        "upstream",
    )
    python_release = upstream["python_sdk"]
    _require_exact_keys(
        python_release,
        {"package", "registry", "stable_version"},
        "upstream.python_sdk",
    )
    if (
        python_release["registry"] != "pypi"
        or any(
            not isinstance(python_release[item], str) or not python_release[item]
            for item in python_release
        )
    ):
        raise DriftCheckError("upstream.python_sdk: invalid PyPI release binding")
    typescript_release = upstream["typescript_sdk"]
    _require_exact_keys(
        typescript_release,
        {"repository", "stable_tag"},
        "upstream.typescript_sdk",
    )
    if any(
        not isinstance(typescript_release[item], str) or not typescript_release[item]
        for item in typescript_release
    ):
        raise DriftCheckError("upstream.typescript_sdk: invalid release binding")
    issue = upstream["protocol_issue"]
    _require_exact_keys(
        issue,
        {"repository", "number", "state"},
        "upstream.protocol_issue",
    )
    pull = upstream["conformance_pull_request"]
    _require_exact_keys(
        pull,
        {"repository", "number", "state", "merged"},
        "upstream.conformance_pull_request",
    )
    for label, value in (
        ("upstream.protocol_issue", issue),
        ("upstream.conformance_pull_request", pull),
    ):
        if (
            not isinstance(value["repository"], str)
            or not value["repository"]
            or not isinstance(value["number"], int)
            or isinstance(value["number"], bool)
            or value["number"] < 1
            or value["state"] not in {"open", "closed"}
        ):
            raise DriftCheckError(f"{label}: invalid GitHub binding")
    if not isinstance(pull["merged"], bool):
        raise DriftCheckError("upstream.conformance_pull_request.merged: expected boolean")


def _validate_repository_result(value: Any, label: str) -> None:
    if not isinstance(value, dict):
        raise DriftCheckError(f"{label}: expected an object")
    _require_exact_keys(
        value,
        {
            "name",
            "path",
            "baseline_commit",
            "current_commit",
            "baseline_tree",
            "current_tree",
            "working_tree_clean",
            "status",
            "changed_paths",
            "material_paths",
            "non_material_paths",
            "limitations",
        },
        label,
    )
    _require_sha(value["baseline_commit"], f"{label}.baseline_commit")
    for key in ("current_commit", "baseline_tree", "current_tree"):
        if value[key]:
            _require_sha(value[key], f"{label}.{key}")
    if not isinstance(value["working_tree_clean"], bool):
        raise DriftCheckError(f"{label}.working_tree_clean: expected boolean")
    if value["status"] not in {
        "CURRENT",
        "HISTORY_ONLY",
        "NON_MATERIAL_DRIFT",
        "MATERIAL_DRIFT",
        "UNKNOWN",
    }:
        raise DriftCheckError(f"{label}.status: invalid status")
    for key in (
        "changed_paths",
        "material_paths",
        "non_material_paths",
        "limitations",
    ):
        if (
            not isinstance(value[key], list)
            or any(not isinstance(item, str) for item in value[key])
        ):
            raise DriftCheckError(f"{label}.{key}: expected strings")


def validate_report_contract(report: Any) -> None:
    if not isinstance(report, dict):
        raise DriftCheckError("report: expected an object")
    validate(report, load_json(REPORT_SCHEMA_PATH))
    _validate_repository_result(report["program"], "program")
    targets = report["targets"]
    if not isinstance(targets, list) or not targets:
        raise DriftCheckError("targets: expected a non-empty array")
    for index, target in enumerate(targets):
        _validate_repository_result(target, f"targets[{index}]")
    upstream = report["upstream"]
    _require_exact_keys(upstream, {"status", "checks", "limitations"}, "upstream")
    if upstream["status"] not in {"CURRENT", "CHANGED", "UNKNOWN"}:
        raise DriftCheckError("upstream.status: invalid status")
    if not isinstance(upstream["checks"], list) or any(
        not isinstance(item, dict) for item in upstream["checks"]
    ):
        raise DriftCheckError("upstream.checks: expected objects")
    if not isinstance(upstream["limitations"], list) or any(
        not isinstance(item, str) for item in upstream["limitations"]
    ):
        raise DriftCheckError("upstream.limitations: expected strings")
    decision = report["decision"]
    _require_exact_keys(
        decision,
        {"status", "reasons", "automatic_epoch_authorized", "next_action"},
        "decision",
    )
    if decision["status"] not in {
        "NO_RERUN_TRIGGER",
        "RERUN_REVIEW_REQUIRED",
        "UNKNOWN",
    }:
        raise DriftCheckError("decision.status: invalid status")
    if decision["automatic_epoch_authorized"] is not False:
        raise DriftCheckError("decision: automatic epoch authority must remain false")


class GitReader:
    """Bounded Git reads under an isolated, no-optional-locks environment."""

    def __init__(self, home: Path) -> None:
        self.home = home
        self.home.mkdir(parents=True, exist_ok=True, mode=0o700)

    def read(self, repository: Path, arguments: list[str], timeout: float = 20) -> bytes:
        environment = {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "HOME": str(self.home.resolve()),
            "XDG_CONFIG_HOME": str((self.home / "xdg").resolve()),
            "GIT_CONFIG_NOSYSTEM": "1",
            "GIT_OPTIONAL_LOCKS": "0",
            "LANG": "C.UTF-8",
            "LC_ALL": "C.UTF-8",
        }
        completed = subprocess.run(
            [
                "git",
                "--no-optional-locks",
                "-C",
                str(repository),
                *arguments,
            ],
            check=False,
            capture_output=True,
            env=environment,
            timeout=timeout,
        )
        if completed.returncode != 0:
            detail = completed.stderr.decode(errors="replace").strip()
            raise DriftCheckError(
                f"{repository.name}: Git read {arguments[0]!r} failed: {detail}"
            )
        return completed.stdout


def _decode_nul_list(value: bytes) -> list[str]:
    return sorted(
        item.decode("utf-8", errors="strict")
        for item in value.split(b"\0")
        if item
    )


def _is_non_material(path: str, patterns: list[str]) -> bool:
    return any(fnmatch.fnmatchcase(path, pattern) for pattern in patterns)


def classify_repository(
    config: dict[str, Any],
    reader: GitReader,
    *,
    name: str,
    baseline_tree: str | None = None,
) -> dict[str, Any]:
    repository = Path(config["path"])
    baseline_commit = config["baseline_commit"]
    result = {
        "name": name,
        "path": str(repository),
        "baseline_commit": baseline_commit,
        "current_commit": "",
        "baseline_tree": baseline_tree or "",
        "current_tree": "",
        "working_tree_clean": False,
        "status": "UNKNOWN",
        "changed_paths": [],
        "material_paths": [],
        "non_material_paths": [],
        "limitations": [],
    }
    try:
        if not repository.is_dir():
            raise DriftCheckError(f"{name}: repository path is unavailable")
        reader.read(repository, ["cat-file", "-e", f"{baseline_commit}^{{commit}}"])
        current_commit = reader.read(repository, ["rev-parse", "HEAD"]).decode().strip()
        current_tree = (
            reader.read(repository, ["rev-parse", "HEAD^{tree}"]).decode().strip()
        )
        observed_baseline_tree = (
            reader.read(
                repository,
                ["rev-parse", f"{baseline_commit}^{{tree}}"],
            )
            .decode()
            .strip()
        )
        if baseline_tree and observed_baseline_tree != baseline_tree:
            raise DriftCheckError(
                f"{name}: stored baseline tree does not match the baseline commit"
            )
        status_bytes = reader.read(
            repository,
            ["status", "--porcelain=v1", "-z", "--untracked-files=all"],
        )
        clean = status_bytes == b""
        changed_paths = _decode_nul_list(
            reader.read(
                repository,
                [
                    "diff",
                    "--name-only",
                    "-z",
                    baseline_commit,
                    current_commit,
                    "--",
                ],
            )
        )
        non_material = [
            path
            for path in changed_paths
            if _is_non_material(path, config["non_material_paths"])
        ]
        material = sorted(set(changed_paths) - set(non_material))
        result.update(
            {
                "current_commit": current_commit,
                "baseline_tree": observed_baseline_tree,
                "current_tree": current_tree,
                "working_tree_clean": clean,
                "changed_paths": changed_paths,
                "material_paths": material,
                "non_material_paths": non_material,
            }
        )
        if not clean:
            result["limitations"].append(
                "Working-tree bytes are not represented by the current commit."
            )
            return result
        if current_commit == baseline_commit:
            result["status"] = "CURRENT"
        elif current_tree == observed_baseline_tree:
            result["status"] = "HISTORY_ONLY"
        elif material:
            result["status"] = "MATERIAL_DRIFT"
        else:
            result["status"] = "NON_MATERIAL_DRIFT"
        return result
    except (DriftCheckError, OSError, UnicodeError, subprocess.TimeoutExpired) as exc:
        result["limitations"].append(str(exc))
        return result


def upstream_json(path: str, timeout: float = 15) -> Any:
    url = path if path.startswith("https://") else f"{API_ROOT}{path}"
    request = Request(
        url,
        headers={
            "Accept": "application/vnd.github+json",
            "User-Agent": "mhai-regression-drift/1",
            "X-GitHub-Api-Version": "2022-11-28",
        },
    )
    try:
        with urlopen(request, timeout=timeout) as response:
            payload = response.read(2 * 1024 * 1024 + 1)
    except (HTTPError, URLError, TimeoutError, OSError) as exc:
        raise DriftCheckError(f"upstream API read failed for {path}: {exc}") from exc
    if len(payload) > 2 * 1024 * 1024:
        raise DriftCheckError(f"upstream API response exceeded the evidence ceiling: {path}")
    try:
        return json.loads(payload)
    except json.JSONDecodeError as exc:
        raise DriftCheckError(f"upstream API returned invalid JSON for {path}") from exc


def _latest_stable_release(
    repository: str,
    api_read: Callable[[str], Any],
) -> dict[str, Any]:
    releases = api_read(f"/repos/{repository}/releases?per_page=100")
    if not isinstance(releases, list):
        raise DriftCheckError(f"{repository}: release response was not a list")
    stable = [
        item
        for item in releases
        if isinstance(item, dict)
        and item.get("draft") is False
        and item.get("prerelease") is False
        and isinstance(item.get("tag_name"), str)
    ]
    if not stable:
        raise DriftCheckError(f"{repository}: no stable release was observable")
    semantic: list[tuple[tuple[int, int, int], dict[str, Any]]] = []
    for release in stable:
        match = re.fullmatch(r"v?(\d+)\.(\d+)\.(\d+)", release["tag_name"])
        if match is not None:
            major, minor, patch = (int(item) for item in match.groups())
            semantic.append(((major, minor, patch), release))
    if semantic:
        return max(semantic, key=lambda item: item[0])[1]
    return max(
        stable,
        key=lambda item: str(item.get("published_at") or item.get("created_at") or ""),
    )


def check_upstream(
    config: dict[str, Any],
    api_read: Callable[[str], Any] = upstream_json,
) -> dict[str, Any]:
    result: dict[str, Any] = {
        "status": "CURRENT",
        "checks": [],
        "limitations": [],
    }
    try:
        python_expected = config["python_sdk"]
        python_payload = api_read(
            f"https://pypi.org/pypi/{python_expected['package']}/json"
        )
        python_info = (
            python_payload.get("info") if isinstance(python_payload, dict) else None
        )
        python_version = (
            python_info.get("version") if isinstance(python_info, dict) else None
        )
        if not isinstance(python_version, str) or not python_version:
            raise DriftCheckError("Python SDK stable PyPI version was unavailable")
        result["checks"].append(
            {
                "kind": "stable_release",
                "repository": f"pypi:{python_expected['package']}",
                "baseline": python_expected["stable_version"],
                "current": python_version,
                "changed": python_version != python_expected["stable_version"],
                "url": f"https://pypi.org/project/{python_expected['package']}/",
            }
        )
        typescript_expected = config["typescript_sdk"]
        release = _latest_stable_release(
            typescript_expected["repository"],
            api_read,
        )
        current_tag = release["tag_name"]
        result["checks"].append(
            {
                "kind": "stable_release",
                "repository": typescript_expected["repository"],
                "baseline": typescript_expected["stable_tag"],
                "current": current_tag,
                "changed": current_tag != typescript_expected["stable_tag"],
                "url": release.get("html_url", ""),
            }
        )
        issue_config = config["protocol_issue"]
        issue = api_read(
            f"/repos/{issue_config['repository']}/issues/{issue_config['number']}"
        )
        issue_state = issue.get("state") if isinstance(issue, dict) else None
        if issue_state not in {"open", "closed"}:
            raise DriftCheckError("protocol issue state was unavailable")
        result["checks"].append(
            {
                "kind": "protocol_issue",
                "repository": issue_config["repository"],
                "number": issue_config["number"],
                "baseline": issue_config["state"],
                "current": issue_state,
                "changed": issue_state != issue_config["state"],
                "url": issue.get("html_url", ""),
            }
        )
        pull_config = config["conformance_pull_request"]
        pull = api_read(
            f"/repos/{pull_config['repository']}/pulls/{pull_config['number']}"
        )
        pull_state = pull.get("state") if isinstance(pull, dict) else None
        merged = pull.get("merged_at") is not None if isinstance(pull, dict) else None
        if pull_state not in {"open", "closed"} or not isinstance(merged, bool):
            raise DriftCheckError("conformance pull-request state was unavailable")
        result["checks"].append(
            {
                "kind": "conformance_pull_request",
                "repository": pull_config["repository"],
                "number": pull_config["number"],
                "baseline_state": pull_config["state"],
                "current_state": pull_state,
                "baseline_merged": pull_config["merged"],
                "current_merged": merged,
                "changed": (
                    pull_state != pull_config["state"]
                    or merged != pull_config["merged"]
                ),
                "url": pull.get("html_url", ""),
            }
        )
        if any(check["changed"] for check in result["checks"]):
            result["status"] = "CHANGED"
    except (DriftCheckError, KeyError, TypeError) as exc:
        result["status"] = "UNKNOWN"
        result["limitations"].append(str(exc))
    return result


def decide(
    program: dict[str, Any],
    targets: list[dict[str, Any]],
    upstream: dict[str, Any],
) -> dict[str, Any]:
    trigger_reasons: list[str] = []
    unknown_reasons: list[str] = []
    if program["status"] == "MATERIAL_DRIFT":
        trigger_reasons.append("Program verdict-affecting paths changed.")
    elif program["status"] == "UNKNOWN":
        unknown_reasons.append("Program drift could not be classified.")
    for target in targets:
        if target["status"] == "MATERIAL_DRIFT":
            trigger_reasons.append(
                f"{target['name']} verdict-affecting paths changed."
            )
        elif target["status"] == "UNKNOWN":
            unknown_reasons.append(f"{target['name']} drift could not be classified.")
    if upstream["status"] == "CHANGED":
        trigger_reasons.append("An upstream SDK or tracked protocol lane changed.")
    elif upstream["status"] == "UNKNOWN":
        unknown_reasons.append("Upstream drift could not be classified.")
    reasons = [*trigger_reasons, *unknown_reasons]
    if trigger_reasons:
        return {
            "status": "RERUN_REVIEW_REQUIRED",
            "reasons": reasons,
            "automatic_epoch_authorized": False,
            "next_action": (
                "Review the material drift, complete target-owner preparation, "
                "and request authority for exactly one new epoch if current-head "
                "assurance is required."
            ),
        }
    if unknown_reasons:
        return {
            "status": "UNKNOWN",
            "reasons": reasons,
            "automatic_epoch_authorized": False,
            "next_action": (
                "Restore the missing read-only evidence before deciding whether "
                "a new epoch is justified."
            ),
        }
    return {
        "status": "NO_RERUN_TRIGGER",
        "reasons": [
            "No verdict-affecting target, program, SDK, or tracked upstream drift was observed."
        ],
        "automatic_epoch_authorized": False,
        "next_action": "Keep the canonical baseline; do not open or rerun an epoch.",
    }


def build_report(
    baseline_path: Path = BASELINE_PATH,
    *,
    api_read: Callable[[str], Any] = upstream_json,
) -> dict[str, Any]:
    baseline = load_json(baseline_path)
    validate_baseline_contract(baseline)
    with tempfile.TemporaryDirectory(prefix="mhai-drift-git-home-") as temporary:
        reader = GitReader(Path(temporary))
        program = classify_repository(
            baseline["program"],
            reader,
            name="integrity-program",
        )
        targets = [
            classify_repository(
                target,
                reader,
                name=target["name"],
                baseline_tree=target["baseline_tree"],
            )
            for target in baseline["targets"]
        ]
    upstream = check_upstream(baseline["upstream"], api_read=api_read)
    report = {
        "schema_version": "MHAI-REGRESSION-DRIFT-1",
        "baseline_id": baseline["baseline_id"],
        "checked_at": datetime.now(UTC).isoformat().replace("+00:00", "Z"),
        "git_read_contract": {
            "isolated_disposable_home": True,
            "optional_locks_environment": "0",
            "no_optional_locks_argument": True,
            "target_fetch_performed": False,
        },
        "mutation_boundary": {
            "target_writes": False,
            "target_repairs": False,
            "epoch_opened": False,
            "rerun_authorized": False,
            "durable_report_written": False,
        },
        "program": program,
        "targets": targets,
        "upstream": upstream,
        "decision": decide(program, targets, upstream),
    }
    validate_report_contract(report)
    return report


def exit_code(report: dict[str, Any]) -> int:
    return {
        "NO_RERUN_TRIGGER": 0,
        "RERUN_REVIEW_REQUIRED": 10,
        "UNKNOWN": 20,
    }[report["decision"]["status"]]


def main(arguments: list[str] | None = None) -> int:
    parser = argparse.ArgumentParser(
        description="Classify drift from the canonical MHAI regression baseline."
    )
    parser.add_argument(
        "--baseline",
        type=Path,
        default=BASELINE_PATH,
        help="machine-readable baseline path",
    )
    args = parser.parse_args(arguments)
    try:
        report = build_report(args.baseline)
    except (DriftCheckError, OSError, ValueError) as exc:
        print(
            json.dumps(
                {
                    "schema_version": "MHAI-REGRESSION-DRIFT-1",
                    "decision": {
                        "status": "UNKNOWN",
                        "automatic_epoch_authorized": False,
                        "reason": str(exc),
                    },
                },
                sort_keys=True,
            )
        )
        return 20
    print(json.dumps(report, indent=2, sort_keys=True))
    return exit_code(report)


if __name__ == "__main__":
    raise SystemExit(main(sys.argv[1:]))
