"""Program-owned exact executor discovery and bounded test invocation."""

from __future__ import annotations

import hashlib
import json
import os
import stat
import zipfile
from pathlib import Path, PurePosixPath
from typing import Any

from harness.execution import ROOT, RunContext
from harness.process_control import run_argv, scrubbed_environment

PCC_HC011_TESTS = {
    "positive_control": "tests::ipc_positive_control_reaches_run_owned_canary",
    "safe_baseline": "tests::registered_ipc_builder_serves_read_only_queue_command",
    "hostile_approval": "tests::registered_ipc_rejects_hostile_proposal_approval_before_effect",
    "hostile_apply": "tests::registered_ipc_rejects_hostile_external_apply_before_effect",
}
PCC_HC011_MARKERS = {
    "positive_control": "MHAI_HC011_POSITIVE_CONTROL=PASS",
    "safe_baseline": "MHAI_HC011_SAFE_BASELINE=PASS",
    "hostile_approval": "MHAI_HC011_HOSTILE_APPROVAL_REJECTED=PASS",
    "hostile_apply": "MHAI_HC011_HOSTILE_APPLY_REJECTED=PASS",
}
PCC_HC012_TEST = (
    "tests::fake_producer_harness_covers_success_failure_cancellation_and_recovery"
)
AIGC_LP007_TESTS = {
    "positive_control": (
        "authority_integrity_tests::full_ipc_adapter_dependency_path_reaches_loopback_sensor"
    ),
    "hostile_non_loopback": (
        "authority_integrity_tests::non_loopback_endpoint_is_rejected_before_dependency_attempt"
    ),
    "malformed": (
        "authority_integrity_tests::malformed_endpoint_is_rejected_without_attempt"
    ),
}
AIGC_LP007_MARKERS = {
    "positive_attempt": "MHAI_LP007_POSITIVE_ATTEMPT_SENSOR=PASS",
    "full_path": "MHAI_LP007_FULL_PATH=PASS",
    "hostile_non_loopback": "MHAI_LP007_NON_LOOPBACK_REJECTED_BEFORE_ATTEMPT=PASS",
    "malformed": "MHAI_LP007_MALFORMED_REJECTED_BEFORE_ATTEMPT=PASS",
}


def file_sha256(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def verify_extracted_archive(archive: Path, destination: Path) -> str:
    """Bind every archived source member to the extracted executor tree."""
    manifest: list[dict[str, str]] = []
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = PurePosixPath(member.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise ValueError(f"unsafe archive member: {member.filename}")
            output = destination.joinpath(*relative.parts)
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if member.is_dir():
                if not output.is_dir():
                    raise ValueError(
                        f"extracted archive directory mismatch: {member.filename}"
                    )
                manifest.append({"path": member.filename, "type": "directory"})
            elif file_type == stat.S_IFLNK:
                expected_target = source.read(member).decode("utf-8")
                if not output.is_symlink() or os.readlink(output) != expected_target:
                    raise ValueError(
                        f"extracted archive symlink mismatch: {member.filename}"
                    )
                manifest.append(
                    {
                        "path": member.filename,
                        "type": "symlink",
                        "target": expected_target,
                    }
                )
            else:
                expected = source.read(member)
                if (
                    not output.is_file()
                    or output.is_symlink()
                    or output.read_bytes() != expected
                ):
                    raise ValueError(
                        f"extracted archive file mismatch: {member.filename}"
                    )
                manifest.append(
                    {
                        "path": member.filename,
                        "type": "file",
                        "sha256": hashlib.sha256(expected).hexdigest(),
                    }
                )
    return hashlib.sha256(
        json.dumps(manifest, sort_keys=True, separators=(",", ":")).encode()
    ).hexdigest()


def executor_root(target: str, head: str) -> Path:
    slugs = {
        "PortfolioCommandCenter": "pcc",
        "AIGCCore": "aigc",
        "portfolio-index": "portfolio-index",
    }
    return ROOT / "work" / "isolated-targets" / "executors" / f"{slugs[target]}-{head}"


def executor_receipt(context: RunContext, case_id: str) -> tuple[dict[str, Any], Path]:
    frozen = context.frozen_target(case_id)
    archive_receipt = frozen["archive"]
    root = executor_root(frozen["name"], frozen["head"])
    path = root / "executor.json"
    if not path.is_file():
        raise FileNotFoundError(f"executor receipt unavailable for {case_id}")
    receipt = json.loads(path.read_text(encoding="utf-8"))
    if (
        receipt.get("schema_version") != "MHAI-TARGET-EXECUTOR-1"
        or receipt.get("source_deviations") != []
        or receipt.get("target") != frozen["name"]
        or receipt.get("head") != frozen["head"]
        or receipt.get("tree") != frozen["tree"]
        or receipt.get("archive_sha256") != archive_receipt.get("sha256")
        or receipt.get("archive_tree_manifest_sha256")
        != archive_receipt.get("tree_manifest_sha256")
    ):
        raise ValueError(f"executor receipt binding mismatch for {case_id}")
    archive_relative = archive_receipt.get("path")
    if not isinstance(archive_relative, str):
        raise ValueError(f"executor archive path unavailable for {case_id}")
    archive = ROOT / archive_relative
    if (
        not archive.is_file()
        or file_sha256(archive) != frozen["archive"].get("sha256")
        or verify_extracted_archive(archive, root)
        != receipt.get("extracted_source_manifest_sha256")
    ):
        raise ValueError(f"executor source binding mismatch for {case_id}")
    return receipt, root


def bound_executable(
    context: RunContext,
    case_id: str,
    required_tests: set[str],
) -> tuple[Path, dict[str, Any], Path]:
    receipt, root = executor_receipt(context, case_id)
    relative = receipt.get("test_executable")
    if not isinstance(relative, str):
        raise ValueError(f"executor receipt has no test executable for {case_id}")
    relative_path = Path(relative)
    if relative_path.is_absolute() or ".." in relative_path.parts:
        raise ValueError(f"executor binary path escapes its root for {case_id}")
    executable = root / relative_path
    if (
        not executable.is_file()
        or not os.access(executable, os.X_OK)
        or file_sha256(executable) != receipt.get("test_executable_sha256")
    ):
        raise ValueError(f"executor binary binding mismatch for {case_id}")
    listed = set(receipt.get("listed_tests", []))
    if not required_tests.issubset(listed):
        raise ValueError(f"executor binary lacks required tests for {case_id}")
    return executable, receipt, root


def run_exact_test(
    *,
    executable: Path,
    test_name: str,
    domain_root: Path,
    timeout_seconds: float = 30,
) -> dict[str, Any]:
    domain_root.mkdir(parents=True, exist_ok=False, mode=0o700)
    environment = scrubbed_environment(
        domain_root,
        {
            "PATH": "/usr/local/bin:/usr/bin:/bin",
            "RUST_TEST_THREADS": "1",
        },
    )
    completed = run_argv(
        [str(executable), test_name, "--exact", "--nocapture"],
        cwd=executable.parents[3],
        environment=environment,
        timeout_seconds=timeout_seconds,
        max_output_bytes=1024 * 1024,
        apply_resource_limits=False,
    )
    stdout_text = completed.stdout.decode(errors="replace")
    stderr_text = completed.stderr.decode(errors="replace")
    payload = {
        "test_name": test_name,
        "returncode": completed.returncode,
        "timed_out": completed.timed_out,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout_tail": stdout_text[-800:],
        "stderr_tail": stderr_text[-800:],
        "home_confined": environment["HOME"].startswith(str(domain_root.resolve())),
        "tmp_confined": environment["TMPDIR"].startswith(str(domain_root.resolve())),
    }
    import shutil

    shutil.rmtree(domain_root)
    payload["cleanup_verified"] = not domain_root.exists()
    return payload
