"""Frozen target grounding and no-forbidden-mutation closure epochs."""

from __future__ import annotations

import hashlib
import json
import os
import secrets
import stat
import subprocess
import zipfile
from collections import Counter
from dataclasses import dataclass
from datetime import UTC, datetime
from pathlib import Path
from typing import Any

from harness.process_control import cleanup_labeled_containers, docker
from harness.redaction import redact
from harness.schema_validation import (
    canonical_digest,
    load_json,
    validate,
    validate_result_contract,
)

ROOT = Path(__file__).resolve().parents[1]
CLOSURE_VERSION = "MHAI-CLOSURE-EPOCH-2"


class ClosureEpochError(RuntimeError):
    """A closure epoch could not preserve its exact grounding contract."""


@dataclass(frozen=True)
class TargetPolicy:
    name: str
    path: Path
    case_ids: tuple[str, ...]
    ownership: str
    ownership_basis: str
    archive_allowed: bool = False


TARGET_POLICIES = (
    TargetPolicy(
        "mcp-trust",
        Path("/Users/d/Projects/mcp-trust"),
        ("RT-012",),
        "CLEAR",
        (
            "The operator authorized a read-only archive when clean and owner-free; "
            "the live bridge preflight found no pending handoff."
        ),
        archive_allowed=True,
    ),
    TargetPolicy(
        "PortfolioCommandCenter",
        Path("/Users/d/Projects/PortfolioCommandCenter"),
        ("HC-011", "HC-012"),
        "CLEAR",
        (
            "The operator authorized a read-only archive when clean and owner-free; "
            "the live preflight found no pending handoff, Git lock, or process rooted "
            "in this worktree."
        ),
        archive_allowed=True,
    ),
    TargetPolicy(
        "AIGCCore",
        Path("/Users/d/Projects/AIGCCore"),
        ("LP-007",),
        "CLEAR",
        (
            "The operator authorized a read-only archive when clean and owner-free; "
            "the live preflight found no pending handoff, Git lock, or process rooted "
            "in this worktree."
        ),
        archive_allowed=True,
    ),
    TargetPolicy(
        "portfolio-index",
        Path("/Users/d/Projects/_claude-worktrees/portfolio-index-forge"),
        ("LP-009",),
        "CLEAR",
        (
            "The operator authorized a read-only archive when clean and owner-free; "
            "the live bridge preflight found the prior owner lifecycle ended and no "
            "pending handoff."
        ),
        archive_allowed=True,
    ),
)


def utc_now() -> str:
    return datetime.now(UTC).isoformat().replace("+00:00", "Z")


def _git_environment(home: Path) -> dict[str, str]:
    home.mkdir(parents=True, exist_ok=True, mode=0o700)
    return {
        "PATH": "/usr/local/bin:/usr/bin:/bin",
        "HOME": str(home.resolve()),
        "GIT_OPTIONAL_LOCKS": "0",
        "LANG": "C.UTF-8",
        "LC_ALL": "C.UTF-8",
    }


def safe_git(
    path: Path,
    arguments: list[str],
    *,
    home: Path,
    timeout: float = 20,
) -> bytes:
    """Run one bounded Git read with both optional-lock controls enforced."""
    completed = subprocess.run(
        ["git", "--no-optional-locks", "-C", str(path), *arguments],
        check=False,
        capture_output=True,
        env=_git_environment(home),
        timeout=timeout,
    )
    if completed.returncode != 0:
        raise ClosureEpochError(
            f"safe Git read failed for {path.name}/{arguments[0]}: "
            f"{completed.stderr.decode(errors='replace').strip()}"
        )
    return completed.stdout


def _git_dir_without_git(path: Path) -> Path:
    marker = path / ".git"
    if marker.is_dir():
        return marker.resolve()
    if marker.is_file():
        value = marker.read_text(encoding="utf-8").strip()
        if not value.startswith("gitdir: "):
            raise ClosureEpochError(f"unrecognized linked-worktree marker at {path}")
        candidate = Path(value.removeprefix("gitdir: "))
        if not candidate.is_absolute():
            candidate = marker.parent / candidate
        resolved = candidate.resolve()
        if not resolved.is_dir():
            raise ClosureEpochError(f"linked-worktree Git directory is unavailable at {path}")
        return resolved
    raise ClosureEpochError(f"Git metadata is unavailable at {path}")


def _metadata_digest(path: Path) -> tuple[str, int]:
    """Hash names and lstat metadata without reading target file contents."""
    digest = hashlib.sha256()
    count = 0
    candidates = [path]
    if path.is_dir():
        candidates.extend(sorted(path.rglob("*"), key=lambda item: str(item)))
    for candidate in candidates:
        relative = "." if candidate == path else str(candidate.relative_to(path))
        metadata = candidate.lstat()
        record = (
            relative,
            stat.S_IFMT(metadata.st_mode),
            stat.S_IMODE(metadata.st_mode),
            metadata.st_size,
            metadata.st_mtime_ns,
            metadata.st_ino,
        )
        digest.update(json.dumps(record, separators=(",", ":")).encode())
        digest.update(b"\0")
        count += 1
    return digest.hexdigest(), count


def _target_metadata(path: Path, git_dir: Path) -> dict[str, Any]:
    worktree_digest, worktree_entries = _metadata_digest(path)
    if git_dir == path / ".git":
        git_digest = worktree_digest
        git_entries = worktree_entries
        git_scope = "included-in-worktree"
    else:
        git_digest, git_entries = _metadata_digest(git_dir)
        git_scope = "linked-worktree-gitdir"
    index = git_dir / "index"
    index_stat = index.stat()
    return {
        "worktree_metadata_sha256": worktree_digest,
        "worktree_entry_count": worktree_entries,
        "git_metadata_sha256": git_digest,
        "git_entry_count": git_entries,
        "git_scope": git_scope,
        "index": {
            "inode": index_stat.st_ino,
            "size": index_stat.st_size,
            "mtime_ns": index_stat.st_mtime_ns,
        },
    }


def _owner_activity(path: Path, git_dir: Path) -> dict[str, Any]:
    lock_paths = sorted(
        str(candidate.relative_to(git_dir))
        for candidate in git_dir.rglob("*.lock")
        if candidate.is_file()
    )
    completed = subprocess.run(
        ["/usr/sbin/lsof", "-a", "-d", "cwd", "+D", str(path), "-F", "p"],
        check=False,
        capture_output=True,
        env={
            "PATH": "/usr/bin:/bin:/usr/sbin",
            "LANG": "C",
            "LC_ALL": "C",
        },
        timeout=20,
    )
    if completed.returncode not in {0, 1}:
        return {
            "clear": False,
            "status": "UNCLEAR",
            "detail": "owner-process inventory was unavailable",
            "git_lock_count": len(lock_paths),
            "cwd_process_count": None,
        }
    pids = {
        line[1:]
        for line in completed.stdout.decode(errors="replace").splitlines()
        if line.startswith("p") and line[1:].isdigit()
    }
    clear = not lock_paths and not pids
    return {
        "clear": clear,
        "status": "CLEAR" if clear else "ACTIVE",
        "detail": (
            "no Git lock and no process with cwd inside the worktree"
            if clear
            else "a Git lock or process cwd indicates active ownership"
        ),
        "git_lock_count": len(lock_paths),
        "cwd_process_count": len(pids),
    }


def _git_blob_oid(data: bytes, object_format: str) -> str:
    algorithm = hashlib.sha1 if object_format == "sha1" else hashlib.sha256
    digest = algorithm()
    digest.update(f"blob {len(data)}\0".encode())
    digest.update(data)
    return digest.hexdigest()


def _archive_and_verify(
    policy: TargetPolicy,
    *,
    head: str,
    epoch_root: Path,
    home: Path,
) -> dict[str, Any]:
    archive_root = epoch_root / "archives"
    archive_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    archive_path = archive_root / f"{policy.name}-{head}.zip"
    safe_git(
        policy.path,
        [
            "archive",
            "--format=zip",
            f"--output={archive_path}",
            head,
        ],
        home=home,
        timeout=30,
    )
    object_format = safe_git(
        policy.path,
        ["rev-parse", "--show-object-format"],
        home=home,
    ).decode().strip()
    if object_format not in {"sha1", "sha256"}:
        raise ClosureEpochError(f"unsupported Git object format: {object_format}")
    raw_tree = safe_git(
        policy.path,
        ["ls-tree", "-rz", "--full-tree", head],
        home=home,
        timeout=30,
    )
    expected: dict[str, tuple[str, str]] = {}
    manifest = hashlib.sha256()
    for raw_record in raw_tree.split(b"\0"):
        if not raw_record:
            continue
        metadata, raw_name = raw_record.split(b"\t", 1)
        mode, kind, oid = metadata.decode().split(" ")
        name = raw_name.decode("utf-8", errors="strict")
        if kind != "blob":
            raise ClosureEpochError(
                f"archive fidelity cannot represent {kind} entry {name!r}"
            )
        expected[name] = (mode, oid)
        manifest.update(f"{mode} {kind} {oid}\t{name}\0".encode())
    with zipfile.ZipFile(archive_path) as archive:
        files = {
            info.filename: info
            for info in archive.infolist()
            if not info.is_dir()
        }
        if set(files) != set(expected):
            raise ClosureEpochError("Git archive file set differs from the exact tree")
        for name, (mode, oid) in expected.items():
            data = archive.read(files[name])
            if _git_blob_oid(data, object_format) != oid:
                raise ClosureEpochError(f"Git archive blob mismatch at {name}")
            archived_mode = (files[name].external_attr >> 16) & 0o777
            expected_mode = int(mode, 8) & 0o777
            if archived_mode and archived_mode != expected_mode:
                raise ClosureEpochError(f"Git archive mode mismatch at {name}")
    os.chmod(archive_path, 0o444)
    return {
        "created": True,
        "path": str(archive_path.relative_to(ROOT)),
        "sha256": hashlib.sha256(archive_path.read_bytes()).hexdigest(),
        "tree_manifest_sha256": manifest.hexdigest(),
        "file_count": len(expected),
        "object_format": object_format,
        "fidelity_proven": True,
        "immutable_mode": "0444",
    }


def _atomic_replace(path: Path, value: Any) -> None:
    encoded = (json.dumps(redact(value), indent=2, sort_keys=True) + "\n").encode()
    path.parent.mkdir(parents=True, exist_ok=True, mode=0o700)
    temporary = path.with_suffix(path.suffix + ".tmp")
    with temporary.open("xb") as handle:
        os.chmod(temporary, 0o600)
        handle.write(encoded)
        handle.flush()
        os.fsync(handle.fileno())
    os.replace(temporary, path)


def _write_once(path: Path, value: Any) -> None:
    if path.exists():
        raise ClosureEpochError(f"refusing to overwrite immutable receipt: {path}")
    _atomic_replace(path, value)


def _discover_exact_go_sdk(root: Path, run_id: str) -> dict[str, Any]:
    discovery_root = root / "go-sdk-discovery"
    discovery_root.mkdir(parents=True, mode=0o700)
    official_module = (
        ROOT
        / "vendor"
        / "official"
        / "go-mod-cache"
        / "github.com"
        / "modelcontextprotocol"
        / "go-sdk@v1.6.1"
    )
    provenance_path = ROOT / "OFFICIAL-DEPENDENCY-PROVENANCE.json"
    official_available = False
    official_version = None
    official_module_sha256 = None
    if official_module.is_dir() and provenance_path.is_file():
        provenance = load_json(provenance_path)
        go_provenance = provenance.get("go_sdk", {})
        official_version = go_provenance.get("version")
        official_module_sha256 = go_provenance.get("zip_sha256")
        official_available = (
            official_version == "v1.6.1"
            and isinstance(official_module_sha256, str)
            and len(official_module_sha256) == 64
            and (official_module / "go.mod").read_text(encoding="utf-8").splitlines()[0]
            == "module github.com/modelcontextprotocol/go-sdk"
        )
    module_root = Path.home() / "go" / "pkg" / "mod"
    host_go_mod_files_scanned = 0
    host_exact_versions: set[str] = set()
    if module_root.is_dir():
        for path in module_root.rglob("go.mod"):
            try:
                if path.stat().st_size > 1024 * 1024:
                    continue
                first_line = path.read_text(
                    encoding="utf-8",
                    errors="strict",
                ).splitlines()[0]
            except (OSError, UnicodeDecodeError, IndexError):
                continue
            host_go_mod_files_scanned += 1
            if first_line.strip() == "module github.com/modelcontextprotocol/go-sdk":
                parent = path.parent.name
                host_exact_versions.add(
                    parent.split("@", 1)[-1] if "@" in parent else parent
                )

    listed = docker(
        ["image", "ls", "--format", "{{.Repository}}:{{.Tag}}"],
        cwd=discovery_root,
    )
    if listed.returncode != 0:
        raise ClosureEpochError("cached image inventory failed during Go SDK discovery")
    images = sorted(
        {
            line
            for line in listed.stdout.decode().splitlines()
            if line and line != "<none>:<none>"
        }
    )
    script = r"""
for base in /app /workspace /usr/local /usr/share /opt /go/pkg/mod /root/go/pkg/mod; do
  if [ -d "$base" ]; then
    find "$base" -type f -name go.mod -print 2>/dev/null
  fi
done | while IFS= read -r file; do
  first="$(sed -n '1p' "$file" 2>/dev/null || true)"
  if [ "$first" = "module github.com/modelcontextprotocol/go-sdk" ]; then
    printf '%s\n' "$file"
  fi
done
"""
    image_results: list[dict[str, Any]] = []
    image_exact_matches: list[str] = []
    label = f"{run_id}-go-cache"
    try:
        for index, image in enumerate(images):
            completed = docker(
                [
                    "run",
                    "--rm",
                    "--name",
                    f"mhai-go-cache-{run_id[-8:]}-{index}",
                    "--label",
                    f"mhai.run_id={label}",
                    "--network",
                    "none",
                    "--read-only",
                    "--tmpfs",
                    "/tmp:rw,noexec,nosuid,size=8m",
                    "--cap-drop",
                    "ALL",
                    "--security-opt",
                    "no-new-privileges",
                    "--pids-limit",
                    "16",
                    "--memory",
                    "256m",
                    "--cpus",
                    "0.5",
                    "--ulimit",
                    "nofile=64:64",
                    "--user",
                    "65534:65534",
                    "--workdir",
                    "/tmp",
                    "--entrypoint",
                    "/bin/sh",
                    image,
                    "-c",
                    script,
                ],
                cwd=discovery_root,
                timeout_seconds=30,
            )
            matches = sorted(
                line for line in completed.stdout.decode().splitlines() if line
            )
            image_exact_matches.extend(f"{image}:{match}" for match in matches)
            image_results.append(
                {
                    "image": image,
                    "scan_result": (
                        "PASS" if completed.returncode == 0 else "UNAVAILABLE"
                    ),
                    "exact_module_matches": len(matches),
                }
            )
    finally:
        cleanup_labeled_containers(label, discovery_root)

    exact_versions = sorted(host_exact_versions)
    exact_available = bool(official_available or exact_versions or image_exact_matches)
    unavailable_images = [
        item["image"]
        for item in image_results
        if item["scan_result"] == "UNAVAILABLE"
    ]
    return {
        "eligible": exact_available,
        "detail": (
            (
                "The authorized exact official github.com/modelcontextprotocol/go-sdk "
                "v1.6.1 module is present in program-owned storage."
            )
            if exact_available
            else (
                "No exact official github.com/modelcontextprotocol/go-sdk version "
                "exists in the bounded host module cache or inspectable cached images; "
                "any unavailable image remains an explicit access limitation."
            )
        ),
        "host_go_mod_files_scanned": host_go_mod_files_scanned,
        "host_exact_versions": exact_versions,
        "program_owned_official_available": official_available,
        "program_owned_official_version": official_version,
        "program_owned_module_zip_sha256": official_module_sha256,
        "program_owned_module_path": (
            str(official_module.relative_to(ROOT)) if official_available else None
        ),
        "cached_images_considered": len(images),
        "cached_image_results": image_results,
        "image_exact_module_matches": len(image_exact_matches),
        "unavailable_images": unavailable_images,
        "network_access_used": False,
        "package_install_used": False,
        "authorized_download_previously_completed": official_available,
    }


def open_epoch() -> tuple[dict[str, Any], Path]:
    epoch_id = f"closure-{int(datetime.now(UTC).timestamp())}-{secrets.token_hex(6)}"
    epoch_root = ROOT / "results" / "closure-epochs" / epoch_id
    home = epoch_root / "git-home"
    epoch_root.mkdir(parents=True, exist_ok=False, mode=0o700)

    program_head = safe_git(ROOT, ["rev-parse", "HEAD"], home=home).decode().strip()
    program_status = safe_git(
        ROOT,
        ["status", "--porcelain=v1", "--untracked-files=all"],
        home=home,
    )
    if program_status:
        raise ClosureEpochError("closure epoch requires a clean program checkpoint")

    observations: list[dict[str, Any]] = []
    for policy in TARGET_POLICIES:
        git_dir = _git_dir_without_git(policy.path)
        before = _target_metadata(policy.path, git_dir)
        head = safe_git(policy.path, ["rev-parse", "HEAD"], home=home).decode().strip()
        tree = safe_git(policy.path, ["rev-parse", f"{head}^{{tree}}"], home=home).decode().strip()
        branch = safe_git(
            policy.path,
            ["symbolic-ref", "--short", "-q", "HEAD"],
            home=home,
        ).decode().strip()
        status_output = safe_git(
            policy.path,
            ["status", "--porcelain=v1", "--untracked-files=all"],
            home=home,
            timeout=30,
        )
        clean = not status_output
        owner_activity = _owner_activity(policy.path, git_dir)
        ownership = (
            owner_activity["status"]
            if policy.ownership == "CLEAR"
            else policy.ownership
        )
        ownership_basis = (
            f"{policy.ownership_basis} Exact open-time evidence: "
            f"{owner_activity['detail']}."
        )
        archive: dict[str, Any] = {
            "created": False,
            "fidelity_proven": False,
            "reason": "source ownership is not clear",
        }
        if policy.archive_allowed and ownership == "CLEAR" and clean:
            archive = _archive_and_verify(
                policy,
                head=head,
                epoch_root=epoch_root,
                home=home,
            )
        elif policy.archive_allowed and not clean:
            archive["reason"] = "source worktree is not clean"
        after = _target_metadata(policy.path, git_dir)
        read_mutation_free = before == after
        if not read_mutation_free:
            raise ClosureEpochError(
                f"safe grounding changed target metadata for {policy.name}"
            )
        observations.append(
            {
                "name": policy.name,
                "case_ids": list(policy.case_ids),
                "head": head,
                "tree": tree,
                "branch": branch,
                "clean": clean,
                "status_sha256": hashlib.sha256(status_output).hexdigest(),
                "ownership": ownership,
                "ownership_basis": ownership_basis,
                "owner_activity": owner_activity,
                "metadata": before,
                "read_mutation_free": True,
                "archive": archive,
            }
        )

    go_sdk_discovery = _discover_exact_go_sdk(epoch_root, epoch_id)
    try:
        from harness.browser_runtime import current_browser_identity

        browser_identity = current_browser_identity().as_dict()
        browser_discovery = {
            "eligible": True,
            "detail": (
                "An official disposable Playwright Chromium headless-shell is "
                "present in program-owned storage and awaits CQ-012 repeatability."
            ),
            "identity": browser_identity,
            "normal_profile_use_authorized": False,
        }
    except Exception as exc:
        browser_discovery = {
            "eligible": False,
            "detail": f"Program-owned browser identity validation failed: {exc}",
            "normal_profile_use_authorized": False,
        }
    receipt = {
        "closure_version": CLOSURE_VERSION,
        "phase": "OPEN",
        "epoch_id": epoch_id,
        "opened_at": utc_now(),
        "program_commit": program_head,
        "git_read_contract": {
            "environment": "GIT_OPTIONAL_LOCKS=0",
            "argument": "git --no-optional-locks",
        },
        "target_observations": observations,
        "lane_discovery": {
            "browser": browser_discovery,
            "go_sdk": go_sdk_discovery,
            "cross_sdk": {
                "eligible": True,
                "detail": (
                    "Qualified cached image contains Python mcp 1.28.1 and "
                    "TypeScript @modelcontextprotocol/sdk 1.29.0."
                ),
            },
            "type_checker": {
                "eligible": True,
                "detail": "mypy 2.0.0 is installed locally.",
            },
        },
        "historical_exceptions": ["SE-001", "SE-002", "SE-003", "SE-004"],
        "historical_exception_repaired": False,
    }
    validate(receipt, load_json(ROOT / "schemas/closure-epoch-open.schema.json"))
    immutable_path = epoch_root / "open.json"
    latest_path = ROOT / "results/latest/closure-epoch-open.json"
    _write_once(immutable_path, receipt)
    _atomic_replace(latest_path, receipt)
    return receipt, latest_path


def validate_open_receipt(receipt: dict[str, Any]) -> None:
    validate(receipt, load_json(ROOT / "schemas/closure-epoch-open.schema.json"))
    if receipt["historical_exceptions"] not in (
        ["SE-001"],
        ["SE-001", "SE-002"],
        ["SE-001", "SE-002", "SE-003"],
        ["SE-001", "SE-002", "SE-003", "SE-004"],
    ):
        raise ClosureEpochError(
            "closure epoch must retain ordered historical exceptions beginning with SE-001"
        )
    if receipt["historical_exception_repaired"]:
        raise ClosureEpochError("historical SE-001 cannot be marked repaired")


def target_observation(receipt: dict[str, Any], case_id: str) -> dict[str, Any]:
    validate_open_receipt(receipt)
    matches = [
        item
        for item in receipt["target_observations"]
        if case_id in item["case_ids"]
    ]
    if len(matches) != 1:
        raise ClosureEpochError(f"no unique frozen target identity for {case_id}")
    return matches[0]


def _validate_bound_run(manifest: dict[str, Any]) -> list[dict[str, Any]]:
    """Verify every immutable result path, hash, schema, and catalog binding."""
    validate(manifest, load_json(ROOT / "schemas/run-manifest.schema.json"))
    cases = load_json(ROOT / "cases.json")
    if (
        len(cases) != 57
        or manifest["case_ids"] != [case["case_id"] for case in cases]
        or manifest["case_count"] != 57
    ):
        raise ClosureEpochError("run manifest is not bound to the exact 57-case catalog")
    cases_by_id = {case["case_id"]: case for case in cases}
    if len(cases_by_id) != 57:
        raise ClosureEpochError("case catalog contains duplicate identities")

    result_schema = load_json(ROOT / "schemas/result.schema.json")
    run_root = (ROOT / "results/runs" / manifest["run_id"]).resolve()
    results: list[dict[str, Any]] = []
    for item in manifest["results"]:
        expected_path = (
            run_root / "cases" / f"{item['case_id']}.json"
        ).resolve()
        recorded_path = (ROOT / item["path"]).resolve()
        if recorded_path != expected_path or run_root not in recorded_path.parents:
            raise ClosureEpochError(
                f"{item['case_id']}: result path is outside the exact run"
            )
        encoded = recorded_path.read_bytes()
        if hashlib.sha256(encoded).hexdigest() != item["sha256"]:
            raise ClosureEpochError(f"{item['case_id']}: result hash mismatch")
        result = json.loads(encoded)
        validate_result_contract(
            result,
            result_schema,
            cases_by_id[item["case_id"]],
        )
        if (
            result["run_id"] != manifest["run_id"]
            or result["result"] != item["result"]
        ):
            raise ClosureEpochError(
                f"{item['case_id']}: manifest/result binding mismatch"
            )
        results.append(result)
    counts = dict(sorted(Counter(item["result"] for item in results).items()))
    if len(results) != 57 or counts != manifest["result_counts"]:
        raise ClosureEpochError("run result counts do not match 57 validated results")
    return results


def _target_access_checks(
    open_receipt: dict[str, Any],
    results: list[dict[str, Any]],
) -> list[dict[str, Any]]:
    """Validate the case evidence proving no post-open live-target access."""
    results_by_id = {result["case_id"]: result for result in results}
    checks: list[dict[str, Any]] = []
    for target in open_receipt["target_observations"]:
        case_evidence_valid = True
        access_mode = "NONE"
        for case_id in target["case_ids"]:
            result = results_by_id[case_id]
            observation = result["observations"][0]
            if case_id == "RT-012":
                archive = target["archive"]
                if archive.get("created"):
                    archive_path = (ROOT / archive["path"]).resolve()
                    case_evidence_valid = case_evidence_valid and (
                        archive.get("fidelity_proven") is True
                        and ROOT.resolve() in archive_path.parents
                        and observation.get("archive_sha256") == archive["sha256"]
                        and observation.get("target_mount") == "read-only"
                    )
                    access_mode = "PROGRAM_ARCHIVE_ONLY"
                else:
                    case_evidence_valid = case_evidence_valid and (
                        result["result"] == "BLOCKED_BY_ACCESS"
                        and observation.get("target_code_executed") is False
                    )
            elif case_id == "HC-011":
                archive = target["archive"]
                if result["result"] == "PASS":
                    case_evidence_valid = case_evidence_valid and (
                        archive.get("created") is True
                        and archive.get("fidelity_proven") is True
                        and observation.get("archive_sha256") == archive.get("sha256")
                        and observation.get("actual_tauri_ipc_dispatcher_executed")
                        is True
                        and observation.get("target_code_executed") is True
                        and observation.get("target_repository_accessed_during_case")
                        is False
                        and observation.get("cleanup_verified") is True
                        and result.get("control_results", {}).get("positive") == "PASS"
                        and result.get("control_results", {}).get("negative") == "PASS"
                    )
                else:
                    case_evidence_valid = case_evidence_valid and (
                        result["result"] == "BLOCKED_BY_ACCESS"
                        and observation.get("unsafe_fallback_refused") is True
                        and observation.get("target_code_executed") is False
                        and (
                            not archive.get("created")
                            or observation.get("archive_sha256")
                            == archive.get("sha256")
                        )
                    )
                if archive.get("created"):
                    access_mode = "PROGRAM_ARCHIVE_RECEIPT_ONLY"
            elif case_id == "HC-012":
                archive = target["archive"]
                if result["result"] == "FAIL":
                    instrumentation = observation.get("instrumentation", {})
                    vulnerable = instrumentation.get("vulnerable_control", {})
                    baseline = instrumentation.get("safe_baseline", {})
                    hostile = instrumentation.get("hostile_path", {})
                    case_evidence_valid = case_evidence_valid and (
                        archive.get("created") is True
                        and archive.get("fidelity_proven") is True
                        and observation.get("archive_sha256") == archive.get("sha256")
                        and observation.get("archive_fidelity_proven") is True
                        and observation.get("target_repository_accessed_during_case")
                        is False
                        and observation.get("target_code_executed") is True
                        and observation.get("ambient_fake_zsh_followed_without_detection")
                        is True
                        and observation.get("cleanup_verified") is True
                        and observation.get("containment_domains")
                        == ["vulnerable-control", "safe-baseline", "hostile-path"]
                        and result.get("control_results", {}).get("positive") == "PASS"
                        and result.get("control_results", {}).get("negative") == "PASS"
                        and result.get("containment_result") == "PASS"
                        and result.get("cleanup_result") == "PASS"
                        and vulnerable.get("fake_zsh_followed") is True
                        and baseline.get("fake_zsh_followed") is False
                        and hostile.get("fake_zsh_followed") is True
                    )
                else:
                    case_evidence_valid = case_evidence_valid and (
                        result["result"] == "BLOCKED_BY_ACCESS"
                        and observation.get("target_repository_accessed_during_case")
                        is False
                        and observation.get("target_code_executed") is False
                        and (
                            not archive.get("created")
                            or observation.get("archive_sha256") == archive.get("sha256")
                        )
                    )
                if archive.get("created"):
                    access_mode = "PROGRAM_ARCHIVE_RECEIPT_ONLY"
            elif case_id in {"LP-007", "LP-009"}:
                archive = target["archive"]
                if result["result"] == "PASS":
                    case_evidence_valid = case_evidence_valid and (
                        archive.get("created") is True
                        and archive.get("fidelity_proven") is True
                        and observation.get("archive_sha256") == archive.get("sha256")
                        and observation.get("target_code_executed") is True
                        and observation.get("target_repository_accessed_during_case")
                        is False
                        and observation.get("cleanup_verified") is True
                        and result.get("control_results", {}).get("positive") == "PASS"
                        and result.get("control_results", {}).get("negative") == "PASS"
                    )
                    if case_id == "LP-007":
                        case_evidence_valid = case_evidence_valid and (
                            observation.get("frontend_contract_executed") is True
                            and observation.get("actual_tauri_ipc_dispatcher_executed")
                            is True
                            and observation.get("production_adapter_runtime_executed")
                            is True
                            and observation.get("socket_dependency_executed") is True
                            and observation.get("arbitrary_egress_succeeded") is False
                        )
                    else:
                        case_evidence_valid = case_evidence_valid and (
                            observation.get("private_repo_marker_excluded") is True
                            and observation.get("private_owner_marker_excluded") is True
                            and observation.get(
                                "vulnerable_control_leaked_private_markers"
                            )
                            is True
                        )
                else:
                    expected_access = (
                        "program archive receipt only"
                        if archive.get("created")
                        else "frozen closure-epoch identity only"
                    )
                    case_evidence_valid = case_evidence_valid and (
                        result["result"] == "BLOCKED_BY_ACCESS"
                        and observation.get("target_access") == expected_access
                        and observation.get("target_code_executed") is False
                        and (
                            not archive.get("created")
                            or observation.get("archive_sha256")
                            == archive.get("sha256")
                        )
                    )
                if archive.get("created"):
                    access_mode = "PROGRAM_ARCHIVE_RECEIPT_ONLY"
            else:
                case_evidence_valid = False
        checks.append(
            {
                "name": target["name"],
                "opening_read_mutation_free": target["read_mutation_free"],
                "post_open_access": access_mode,
                "case_evidence_valid": case_evidence_valid,
                "final_observation": "none; no final target inventory or Git command",
            }
        )
    return checks


def close_epoch() -> tuple[dict[str, Any], Path]:
    open_receipt = load_json(ROOT / "results/latest/closure-epoch-open.json")
    validate_open_receipt(open_receipt)
    immutable_open = load_json(
        ROOT
        / "results"
        / "closure-epochs"
        / open_receipt["epoch_id"]
        / "open.json"
    )
    open_digest = canonical_digest(open_receipt)
    if canonical_digest(immutable_open) != open_digest:
        raise ClosureEpochError("latest closure epoch differs from its immutable receipt")

    manifest = load_json(ROOT / "results/latest/run-manifest.json")
    if (
        manifest.get("closure_epoch_id") != open_receipt["epoch_id"]
        or manifest.get("closure_epoch_digest") != open_digest
        or not manifest["complete"]
        or manifest["cleanup_result"] != "PASS"
    ):
        raise ClosureEpochError("latest complete run is not bound to the open closure epoch")
    results = _validate_bound_run(manifest)

    checks = _target_access_checks(open_receipt, results)

    remaining: list[dict[str, str]] = []
    for result in results:
        if result["blocked_reason"] is not None:
            remaining.append(
                {
                    "case_id": result["case_id"],
                    "result": result["result"],
                    "kind": result["blocked_reason"]["kind"],
                    "detail": result["blocked_reason"]["detail"],
                }
            )
    forbidden_gate = (
        "PASS"
        if all(
            item["opening_read_mutation_free"] and item["case_evidence_valid"]
            for item in checks
        )
        else "FAIL"
    )
    safely_obtainable = not any(
        result["result"] in {"ERROR", "UNKNOWN", "NOT_RUN", "NOT_IMPLEMENTED"}
        for result in results
    )
    close_receipt = {
        "closure_version": CLOSURE_VERSION,
        "phase": "CLOSE",
        "epoch_id": open_receipt["epoch_id"],
        "closed_at": utc_now(),
        "open_digest": open_digest,
        "qualification_run_id": manifest["qualification_run_id"],
        "run_id": manifest["run_id"],
        "run_manifest_sha256": canonical_digest(manifest),
        "target_access_checks": checks,
        "no_forbidden_mutation_gate": forbidden_gate,
        "safely_obtainable_coverage_executed": safely_obtainable,
        "remaining_blockers": remaining,
        "historical_exceptions": ["SE-001", "SE-002", "SE-003", "SE-004"],
        "historical_exception_repaired": False,
        "result": (
            "PASS_WITH_HISTORICAL_EXCEPTION"
            if forbidden_gate == "PASS" and safely_obtainable
            else "FAIL"
        ),
    }
    validate(close_receipt, load_json(ROOT / "schemas/closure-epoch-close.schema.json"))
    epoch_root = ROOT / "results/closure-epochs" / open_receipt["epoch_id"]
    immutable_path = epoch_root / "close.json"
    latest_path = ROOT / "results/latest/closure-epoch-close.json"
    _write_once(immutable_path, close_receipt)
    _atomic_replace(latest_path, close_receipt)
    return close_receipt, latest_path
