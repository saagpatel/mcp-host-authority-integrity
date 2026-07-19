#!/usr/bin/env python3
"""Prepare exact executors from the latest immutable closure-epoch archives."""

from __future__ import annotations

import json
import os
import shutil
import stat
import subprocess
import sys
import zipfile
from pathlib import Path, PurePosixPath

ROOT = Path(__file__).resolve().parents[1]
sys.path.insert(0, str(ROOT))

from harness.schema_validation import load_json  # noqa: E402
from harness.target_executors import (  # noqa: E402
    AIGC_LP007_TESTS,
    PCC_HC011_TESTS,
    PCC_HC012_TEST,
    executor_root,
    file_sha256,
    verify_extracted_archive,
)

CARGO = shutil.which("cargo")
PROGRAM_CARGO_HOME = ROOT / "vendor" / "official" / "cargo-home"
PROVENANCE = load_json(ROOT / "OFFICIAL-DEPENDENCY-PROVENANCE.json")


def safe_extract(archive: Path, destination: Path) -> None:
    if destination.exists():
        shutil.rmtree(destination)
    destination.mkdir(parents=True, mode=0o700)
    with zipfile.ZipFile(archive) as source:
        for member in source.infolist():
            relative = PurePosixPath(member.filename)
            if relative.is_absolute() or ".." in relative.parts:
                raise RuntimeError(f"unsafe archive member: {member.filename}")
            output = destination.joinpath(*relative.parts)
            if member.is_dir():
                output.mkdir(parents=True, exist_ok=True)
                continue
            output.parent.mkdir(parents=True, exist_ok=True)
            file_type = stat.S_IFMT(member.external_attr >> 16)
            if file_type == stat.S_IFLNK:
                link_target = source.read(member).decode("utf-8")
                target_path = PurePosixPath(link_target)
                if target_path.is_absolute() or ".." in target_path.parts:
                    raise RuntimeError(
                        f"unsafe archive symlink: {member.filename} -> {link_target}"
                    )
                output.symlink_to(link_target)
                continue
            with source.open(member) as reader, output.open("wb") as writer:
                shutil.copyfileobj(reader, writer)
            mode = (member.external_attr >> 16) & 0o777
            output.chmod(mode or 0o600)


def cargo_environment(root: Path) -> dict[str, str]:
    home = root / ".executor-home"
    for child in ("home", "tmp", "cache", "config", "state"):
        (home / child).mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "PATH": "/opt/homebrew/bin:/usr/local/bin:/usr/bin:/bin",
        "HOME": str((home / "home").resolve()),
        "TMPDIR": str((home / "tmp").resolve()),
        "XDG_CACHE_HOME": str((home / "cache").resolve()),
        "XDG_CONFIG_HOME": str((home / "config").resolve()),
        "XDG_STATE_HOME": str((home / "state").resolve()),
        "CARGO_HOME": str(PROGRAM_CARGO_HOME.resolve()),
        "CARGO_NET_OFFLINE": "true",
        "RUSTUP_HOME": str((Path.home() / ".rustup").resolve()),
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def run(arguments: list[str], *, cwd: Path, environment: dict[str, str]) -> bytes:
    completed = subprocess.run(
        arguments,
        cwd=cwd,
        env=environment,
        check=False,
        capture_output=True,
        timeout=900,
    )
    if completed.returncode != 0:
        raise RuntimeError(
            f"executor preparation failed: {' '.join(arguments)}\n"
            f"{completed.stdout.decode(errors='replace')[-4000:]}\n"
            f"{completed.stderr.decode(errors='replace')[-4000:]}"
        )
    return completed.stdout


def select_test_binary(
    candidates: list[Path],
    required_tests: set[str],
    *,
    environment: dict[str, str],
) -> tuple[Path, list[str]]:
    matches: list[tuple[Path, list[str]]] = []
    for candidate in candidates:
        if not candidate.is_file() or not os.access(candidate, os.X_OK):
            continue
        output = run([str(candidate), "--list"], cwd=candidate.parents[3], environment=environment)
        listed = sorted(
            line.split(": test", 1)[0]
            for line in output.decode(errors="replace").splitlines()
            if line.endswith(": test")
        )
        if required_tests.issubset(set(listed)):
            matches.append((candidate, listed))
    if len(matches) != 1:
        raise RuntimeError(
            f"expected exactly one test executable, found {len(matches)} for {required_tests}"
        )
    return matches[0]


def prepare_rust_target(
    target: dict,
    *,
    manifest: str,
    lockfile_path: str,
    executable_glob: str,
    required_tests: set[str],
    feature: str | None = None,
) -> dict:
    archive = target["archive"]
    if not (archive.get("created") and archive.get("fidelity_proven")):
        raise RuntimeError(f"no exact archive for {target['name']}")
    archive_path = ROOT / archive["path"]
    if file_sha256(archive_path) != archive["sha256"]:
        raise RuntimeError(f"archive digest mismatch for {target['name']}")
    destination = executor_root(target["name"], target["head"])
    safe_extract(archive_path, destination)
    extracted_source_manifest_sha256 = verify_extracted_archive(
        archive_path,
        destination,
    )
    lockfile = destination / lockfile_path
    provenance_key = (
        "portfolio_command_center"
        if target["name"] == "PortfolioCommandCenter"
        else "aigc_core"
    )
    expected_lock = PROVENANCE["cargo_locked_archives"][provenance_key][
        "cargo_lock_sha256"
    ]
    if file_sha256(lockfile) != expected_lock:
        raise RuntimeError(f"Cargo.lock digest mismatch for {target['name']}")
    if CARGO is None:
        raise RuntimeError("cargo executable unavailable")
    environment = cargo_environment(destination)
    arguments = [
        CARGO,
        "test",
        "--manifest-path",
        manifest,
        "--offline",
        "--locked",
        "--no-run",
    ]
    if feature:
        arguments.extend(["--features", feature])
    run(arguments, cwd=destination, environment=environment)
    if (
        verify_extracted_archive(archive_path, destination)
        != extracted_source_manifest_sha256
    ):
        raise RuntimeError(f"archived source changed during build for {target['name']}")
    candidates = sorted(destination.glob(executable_glob))
    executable, listed_tests = select_test_binary(
        candidates,
        required_tests,
        environment=environment,
    )
    receipt = {
        "schema_version": "MHAI-TARGET-EXECUTOR-1",
        "target": target["name"],
        "head": target["head"],
        "tree": target["tree"],
        "archive_sha256": archive["sha256"],
        "archive_tree_manifest_sha256": archive["tree_manifest_sha256"],
        "cargo_lock_sha256": expected_lock,
        "cargo_offline": True,
        "cargo_home": str(PROGRAM_CARGO_HOME.relative_to(ROOT)),
        "features": [feature] if feature else [],
        "extracted_source_manifest_sha256": extracted_source_manifest_sha256,
        "source_deviations": [],
        "test_executable": str(executable.relative_to(destination)),
        "test_executable_sha256": file_sha256(executable),
        "listed_tests": listed_tests,
    }
    (destination / "executor.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def prepare_source_only(target: dict) -> dict:
    archive = target["archive"]
    if not (archive.get("created") and archive.get("fidelity_proven")):
        raise RuntimeError(f"no exact archive for {target['name']}")
    archive_path = ROOT / archive["path"]
    if file_sha256(archive_path) != archive["sha256"]:
        raise RuntimeError(f"archive digest mismatch for {target['name']}")
    destination = executor_root(target["name"], target["head"])
    safe_extract(archive_path, destination)
    extracted_source_manifest_sha256 = verify_extracted_archive(
        archive_path,
        destination,
    )
    receipt = {
        "schema_version": "MHAI-TARGET-EXECUTOR-1",
        "target": target["name"],
        "head": target["head"],
        "tree": target["tree"],
        "archive_sha256": archive["sha256"],
        "archive_tree_manifest_sha256": archive["tree_manifest_sha256"],
        "extracted_source_manifest_sha256": extracted_source_manifest_sha256,
        "source_deviations": [],
    }
    (destination / "executor.json").write_text(
        json.dumps(receipt, indent=2, sort_keys=True) + "\n",
        encoding="utf-8",
    )
    return receipt


def main() -> int:
    epoch = load_json(ROOT / "results" / "latest" / "closure-epoch-open.json")
    targets = {item["name"]: item for item in epoch["target_observations"]}
    preparations = [
        (
            targets["PortfolioCommandCenter"],
            lambda: prepare_rust_target(
                targets["PortfolioCommandCenter"],
                manifest="src-tauri/Cargo.toml",
                lockfile_path="src-tauri/Cargo.lock",
                executable_glob=(
                    "src-tauri/target/debug/deps/portfolio_command_center_lib-*"
                ),
                required_tests={*PCC_HC011_TESTS.values(), PCC_HC012_TEST},
            ),
        ),
        (
            targets["AIGCCore"],
            lambda: prepare_rust_target(
                targets["AIGCCore"],
                manifest="src-tauri/Cargo.toml",
                lockfile_path="Cargo.lock",
                executable_glob="target/debug/deps/aigc_core_tauri-*",
                required_tests=set(AIGC_LP007_TESTS.values()),
                feature="authority-integrity-test-hooks",
            ),
        ),
        (
            targets["portfolio-index"],
            lambda: prepare_source_only(targets["portfolio-index"]),
        ),
    ]
    receipts = []
    skipped = []
    for target, prepare in preparations:
        archive = target["archive"]
        if not (archive.get("created") and archive.get("fidelity_proven")):
            skipped.append(
                {
                    "target": target["name"],
                    "head": target["head"],
                    "reason": archive.get("reason", "exact archive unavailable"),
                }
            )
            continue
        receipts.append(prepare())
    print(
        json.dumps(
            {
                "epoch_id": epoch["epoch_id"],
                "prepared": [
                    {
                        "target": receipt["target"],
                        "head": receipt["head"],
                        "executable_sha256": receipt.get("test_executable_sha256"),
                    }
                    for receipt in receipts
                ],
                "skipped": skipped,
            },
            sort_keys=True,
        )
    )
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
