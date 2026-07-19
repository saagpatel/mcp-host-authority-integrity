"""Deterministic, synthetic Host Confused Deputy suite oracles.

The non-browser cases in this module are pure in-memory models. They exercise a
deliberately vulnerable positive control and a fail-closed negative control
without opening sockets, reading target repositories, or touching a filesystem.
Browser-dependent cases route through the shared browser policy and never fall
back to simulated browser evidence.
"""

from __future__ import annotations

import hashlib
import json
import os
import posixpath
import shutil
from collections.abc import Callable
from dataclasses import dataclass
from pathlib import Path
from typing import Any

from harness.execution import Evaluation, RunContext, browser_block
from harness.process_control import run_argv, scrubbed_environment

ROOT = Path(__file__).resolve().parents[1]
PCC_HC012_COMMIT = "772be25eed8554defa55505cadd23e7fc61df982"
PCC_HC012_ARCHIVE_SHA256 = (
    "3494719b24d3ebfda24c97dbf363c1958f850f553fec98dd462094cb017111e9"
)
PCC_HC012_CARGO_LOCK_SHA256 = (
    "c963d4103c730eddf6fe269f8b941623d1e70b7c4cc6ab9b71ac0cdf3c7b8445"
)
PCC_HC012_TEST_NAME = "tests::fake_producer_harness_covers_success_failure_cancellation_and_recovery"

_BROWSER_CASES = frozenset({"HC-001", "HC-005", "HC-006", "HC-009", "HC-011"})
_SYNTHETIC_CASES = frozenset({"HC-002", "HC-003", "HC-004", "HC-007", "HC-008", "HC-010"})
_SUPPORTED_CASES = _BROWSER_CASES | _SYNTHETIC_CASES | {"HC-012"}


def _control_evaluation(
    case_id: str,
    observations: list[dict[str, Any]],
    *,
    vulnerable_control_detected: bool,
    safe_subject_rejected_attack: bool,
) -> Evaluation:
    """Build an Evaluation while making invalid controls terminal errors."""

    positive = "PASS" if vulnerable_control_detected else "FAIL"
    negative = "PASS" if safe_subject_rejected_attack else "FAIL"
    observations.append(
        {
            "kind": "control-summary",
            "case_id": case_id,
            "execution_mode": "pure-in-memory",
            "vulnerable_control_reached_forbidden_boundary": vulnerable_control_detected,
            "safe_subject_rejected_attack": safe_subject_rejected_attack,
            "external_effects_attempted": False,
        }
    )
    if positive != "PASS" or negative != "PASS":
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control=positive,
            negative_control=negative,
            declared_result="ERROR",
            limitations=["A synthetic control was invalid, so no target verdict is admissible."],
        )
    return Evaluation(
        target_verdict="PASS",
        observations=observations,
        positive_control=positive,
        negative_control=negative,
        limitations=[
            "This is deterministic fixture-host evidence, not proof about an installed host."
        ],
    )


@dataclass(frozen=True)
class _Tool:
    server: str
    name: str
    visible_to: frozenset[str]


class _VisibilityHost:
    def __init__(self, tools: tuple[_Tool, ...]) -> None:
        self._tools = {(tool.server, tool.name): tool for tool in tools}

    def discover(self, caller: str, server: str) -> list[str]:
        return sorted(
            tool.name
            for tool in self._tools.values()
            if tool.server == server and caller in tool.visible_to
        )

    def invoke(
        self,
        caller: str,
        bound_server: str,
        requested_server: str,
        tool_name: str,
    ) -> _Tool | None:
        if requested_server != bound_server:
            return None
        tool = self._tools.get((bound_server, tool_name))
        if tool is None or caller not in tool.visible_to:
            return None
        return tool


class _NameOnlyVisibilityHost:
    """Positive control: indexes tools only by name and ignores visibility."""

    def __init__(self, tools: tuple[_Tool, ...]) -> None:
        self._tools = {tool.name: tool for tool in tools}

    def discover(self) -> list[str]:
        return sorted(self._tools)

    def invoke(self, tool_name: str) -> _Tool | None:
        return self._tools.get(tool_name)


def _evaluate_hc_002() -> Evaluation:
    tools = (
        _Tool("server-a", "render", frozenset({"app"})),
        _Tool("server-a", "summarize", frozenset({"model"})),
        _Tool("server-a", "shared", frozenset({"app", "model"})),
        # The later same-named sibling wins in the deliberately broken name-only index.
        _Tool("server-b", "render", frozenset({"app"})),
        _Tool("server-b", "server-b-only", frozenset({"app"})),
    )
    safe = _VisibilityHost(tools)
    vulnerable = _NameOnlyVisibilityHost(tools)

    vulnerable_selection = vulnerable.invoke("render")
    safe_cross_server = safe.invoke("app", "server-a", "server-b", "render")
    safe_local = safe.invoke("app", "server-a", "server-a", "render")
    safe_app_discovery = safe.discover("app", "server-a")
    safe_model_discovery = safe.discover("model", "server-a")

    vulnerable_detected = (
        vulnerable_selection is not None
        and vulnerable_selection.server == "server-b"
        and "server-b-only" in vulnerable.discover()
    )
    safe_rejected = (
        safe_cross_server is None
        and safe_local is not None
        and safe_local.server == "server-a"
        and safe_app_discovery == ["render", "shared"]
        and safe_model_discovery == ["shared", "summarize"]
    )
    return _control_evaluation(
        "HC-002",
        [
            {
                "kind": "tool-visibility-matrix",
                "safe_app_server_a": safe_app_discovery,
                "safe_model_server_a": safe_model_discovery,
                "safe_cross_server_invocation": "rejected",
                "vulnerable_same_name_selected_server": (
                    vulnerable_selection.server if vulnerable_selection else None
                ),
            }
        ],
        vulnerable_control_detected=vulnerable_detected,
        safe_subject_rejected_attack=safe_rejected,
    )


@dataclass(frozen=True)
class _AppBinding:
    frame: str
    server: str
    connection: str


class _ConnectionBoundHost:
    def __init__(self) -> None:
        self._app_tools = {
            ("server-a", "connection-a", "app-action"),
            ("server-b", "connection-b", "app-action"),
        }

    def invoke(
        self,
        binding: _AppBinding,
        *,
        request_server: str,
        request_connection: str,
        tool_name: str,
    ) -> bool:
        if (request_server, request_connection) != (binding.server, binding.connection):
            return False
        return (binding.server, binding.connection, tool_name) in self._app_tools


class _UnboundAppHost:
    """Positive control: accepts any globally known app-only tool name."""

    def invoke(self, *, tool_name: str) -> bool:
        return tool_name == "app-action"


def _evaluate_hc_003() -> Evaluation:
    binding = _AppBinding("frame-a", "server-a", "connection-a")
    safe = _ConnectionBoundHost()
    vulnerable = _UnboundAppHost()
    vulnerable_cross_call = vulnerable.invoke(tool_name="app-action")
    safe_cross_call = safe.invoke(
        binding,
        request_server="server-b",
        request_connection="connection-b",
        tool_name="app-action",
    )
    safe_local_call = safe.invoke(
        binding,
        request_server="server-a",
        request_connection="connection-a",
        tool_name="app-action",
    )
    return _control_evaluation(
        "HC-003",
        [
            {
                "kind": "server-connection-binding",
                "synthetic_frame": binding.frame,
                "vulnerable_sibling_call": "accepted" if vulnerable_cross_call else "rejected",
                "safe_sibling_call": "accepted" if safe_cross_call else "rejected",
                "safe_bound_call": "accepted" if safe_local_call else "rejected",
            }
        ],
        vulnerable_control_detected=vulnerable_cross_call,
        safe_subject_rejected_attack=not safe_cross_call and safe_local_call,
    )


def _content_digest(content: str) -> str:
    return hashlib.sha256(content.encode()).hexdigest()


class _DigestReviewCache:
    def __init__(self) -> None:
        self._reviewed: dict[str, str] = {}

    def approve(self, uri: str, content: str) -> None:
        self._reviewed[uri] = _content_digest(content)

    def may_render(self, uri: str, content: str) -> bool:
        return self._reviewed.get(uri) == _content_digest(content)


class _UriOnlyReviewCache:
    """Positive control: treats a stable URI as stable executable content."""

    def __init__(self) -> None:
        self._reviewed: set[str] = set()

    def approve(self, uri: str) -> None:
        self._reviewed.add(uri)

    def may_render(self, uri: str) -> bool:
        return uri in self._reviewed


def _evaluate_hc_004() -> Evaluation:
    uri = "ui://synthetic/template"
    reviewed = "<main>reviewed fixture</main>"
    changed = "<main data-action='synthetic-canary'>changed fixture</main>"

    safe = _DigestReviewCache()
    safe.approve(uri, reviewed)
    vulnerable = _UriOnlyReviewCache()
    vulnerable.approve(uri)

    vulnerable_reuse = vulnerable.may_render(uri)
    safe_before_change = safe.may_render(uri, reviewed)
    safe_after_change = safe.may_render(uri, changed)
    safe.approve(uri, changed)
    safe_after_revalidation = safe.may_render(uri, changed)
    return _control_evaluation(
        "HC-004",
        [
            {
                "kind": "template-review-cache",
                "uri_stable": True,
                "content_digest_changed": _content_digest(reviewed) != _content_digest(changed),
                "vulnerable_reused_prior_review": vulnerable_reuse,
                "safe_render_before_change": safe_before_change,
                "safe_render_after_change_before_review": safe_after_change,
                "safe_render_after_revalidation": safe_after_revalidation,
            }
        ],
        vulnerable_control_detected=vulnerable_reuse,
        safe_subject_rejected_attack=(
            safe_before_change and not safe_after_change and safe_after_revalidation
        ),
    )


class _ProvenanceContext:
    def __init__(self) -> None:
        self.host_instruction = "host-policy: preserve authority"
        self._app_entries: list[dict[str, str]] = []

    def add_app_context(self, value: str, *, frame: str, document: str) -> None:
        self._app_entries.append(
            {
                "value": value,
                "source": "app",
                "authority": "untrusted",
                "frame": frame,
                "document": document,
            }
        )

    def replace_host_instruction(self, _value: str) -> bool:
        return False

    def end_document(self, document: str) -> None:
        self._app_entries = [
            entry for entry in self._app_entries if entry["document"] != document
        ]

    @property
    def app_entries(self) -> list[dict[str, str]]:
        return [dict(entry) for entry in self._app_entries]


class _OverlayContext:
    """Positive control: merges app keys into host state and persists them."""

    def __init__(self) -> None:
        self.state = {"host_instruction": "host-policy: preserve authority"}

    def apply(self, update: dict[str, str]) -> None:
        self.state.update(update)


def _evaluate_hc_007() -> Evaluation:
    injected = "app-content: synthetic lower-authority instruction"
    vulnerable = _OverlayContext()
    vulnerable.apply({"host_instruction": injected, "persisted": "true"})

    safe = _ProvenanceContext()
    replacement_accepted = safe.replace_host_instruction(injected)
    safe.add_app_context(injected, frame="frame-a", document="document-a")
    labelled_before_cleanup = safe.app_entries
    safe.end_document("document-a")

    vulnerable_detected = (
        vulnerable.state["host_instruction"] == injected
        and vulnerable.state.get("persisted") == "true"
    )
    safe_rejected = (
        not replacement_accepted
        and safe.host_instruction == "host-policy: preserve authority"
        and len(labelled_before_cleanup) == 1
        and labelled_before_cleanup[0]["source"] == "app"
        and labelled_before_cleanup[0]["authority"] == "untrusted"
        and safe.app_entries == []
    )
    return _control_evaluation(
        "HC-007",
        [
            {
                "kind": "context-authority",
                "vulnerable_host_context_overwritten": vulnerable_detected,
                "safe_host_context_preserved": safe.host_instruction
                == "host-policy: preserve authority",
                "safe_app_context_authority": labelled_before_cleanup[0]["authority"],
                "safe_document_cleanup_count": len(safe.app_entries),
            }
        ],
        vulnerable_control_detected=vulnerable_detected,
        safe_subject_rejected_attack=safe_rejected,
    )


class _InertFallbackClient:
    def __init__(self) -> None:
        self.sensor_hits = 0

    def consume(self, content: str) -> tuple[str, str]:
        return ("inert_text", content)


class _ExecutingFallbackClient:
    """Positive control: interprets a synthetic marker as executable."""

    def __init__(self) -> None:
        self.sensor_hits = 0

    def consume(self, content: str) -> str:
        if "data-synthetic-canary" in content:
            self.sensor_hits += 1
            return "executed"
        return "text"


def _evaluate_hc_008() -> Evaluation:
    hostile_looking = "<app data-synthetic-canary='1'>fixture only</app>"
    vulnerable = _ExecutingFallbackClient()
    vulnerable_mode = vulnerable.consume(hostile_looking)
    safe = _InertFallbackClient()
    safe_mode, preserved = safe.consume(hostile_looking)

    vulnerable_detected = vulnerable_mode == "executed" and vulnerable.sensor_hits == 1
    safe_rejected = (
        safe_mode == "inert_text"
        and safe.sensor_hits == 0
        and preserved == hostile_looking
    )
    return _control_evaluation(
        "HC-008",
        [
            {
                "kind": "unsupported-app-fallback",
                "payload_sha256": _content_digest(hostile_looking),
                "vulnerable_mode": vulnerable_mode,
                "vulnerable_sensor_hits": vulnerable.sensor_hits,
                "safe_mode": safe_mode,
                "safe_sensor_hits": safe.sensor_hits,
                "safe_preserved_text": preserved == hostile_looking,
            }
        ],
        vulnerable_control_detected=vulnerable_detected,
        safe_subject_rejected_attack=safe_rejected,
    )


def _is_within(candidate: str, root: str) -> bool:
    return candidate == root or candidate.startswith(root.rstrip("/") + "/")


def _expand_virtual_links(path: str, links: dict[str, str]) -> str:
    expanded = path
    for _ in range(len(links) + 1):
        changed = False
        for link, target in sorted(links.items(), key=lambda item: len(item[0]), reverse=True):
            if expanded == link or expanded.startswith(link.rstrip("/") + "/"):
                suffix = expanded[len(link) :].lstrip("/")
                expanded = posixpath.normpath(posixpath.join(target, suffix))
                changed = True
                break
        if not changed:
            return expanded
    return expanded


class _CanonicalRootHost:
    def __init__(self) -> None:
        self.roots = {"current": "/workspace/current"}
        self.links = {"/workspace/current/link": "/outside"}

    def authorize(self, root_id: str, supplied_path: str) -> bool:
        root = self.roots.get(root_id)
        if root is None:
            return False
        candidate = (
            supplied_path
            if supplied_path.startswith("/")
            else posixpath.join(root, supplied_path)
        )
        normalized = posixpath.normpath(candidate)
        expanded = _expand_virtual_links(normalized, self.links)
        return _is_within(expanded, root)


class _PrefixOnlyRootHost:
    """Positive control: trusts raw prefixes and stale roots."""

    def __init__(self) -> None:
        self.roots = {
            "current": "/workspace/current",
            "removed": "/workspace/removed",
        }

    def authorize(self, root_id: str, supplied_path: str) -> bool:
        root = self.roots.get(root_id)
        if root is None:
            return False
        candidate = (
            supplied_path
            if supplied_path.startswith("/")
            else posixpath.join(root, supplied_path)
        )
        return candidate.startswith(root)


def _evaluate_hc_010() -> Evaluation:
    attacks = {
        "traversal": ("current", "/workspace/current/../outside/secret"),
        "symlink": ("current", "/workspace/current/link/secret"),
        "changed_root": ("current", "/workspace/old/secret"),
        "removed_root": ("removed", "/workspace/removed/secret"),
        "direct_route": ("current", "/outside/secret"),
    }
    safe = _CanonicalRootHost()
    vulnerable = _PrefixOnlyRootHost()
    safe_results = {
        name: safe.authorize(root_id, path)
        for name, (root_id, path) in attacks.items()
    }
    vulnerable_results = {
        name: vulnerable.authorize(root_id, path)
        for name, (root_id, path) in attacks.items()
    }
    safe_legitimate = safe.authorize("current", "docs/fixture.txt")

    vulnerable_detected = any(vulnerable_results.values())
    safe_rejected = not any(safe_results.values()) and safe_legitimate
    return _control_evaluation(
        "HC-010",
        [
            {
                "kind": "canonical-root-matrix",
                "safe_attack_authorizations": safe_results,
                "vulnerable_attack_authorizations": vulnerable_results,
                "safe_legitimate_authorization": safe_legitimate,
                "filesystem_access_performed": False,
            }
        ],
        vulnerable_control_detected=vulnerable_detected,
        safe_subject_rejected_attack=safe_rejected,
    )


_EVALUATORS: dict[str, Callable[[], Evaluation]] = {
    "HC-002": _evaluate_hc_002,
    "HC-003": _evaluate_hc_003,
    "HC-004": _evaluate_hc_004,
    "HC-007": _evaluate_hc_007,
    "HC-008": _evaluate_hc_008,
    "HC-010": _evaluate_hc_010,
}


def _browser_refusal(case: dict[str, Any], context: RunContext) -> Evaluation:
    blocked = browser_block(case, context)
    if blocked is not None:
        return blocked
    if case["case_id"] in {"HC-001", "HC-005", "HC-006", "HC-009"}:
        from suite_impl.browser_fixtures import evaluate_hc

        return evaluate_hc(case, context)
    if case["case_id"] == "HC-011":
        frozen = context.frozen_target("HC-011")
        archive = frozen["archive"]
        archive_available = bool(
            archive.get("created") and archive.get("fidelity_proven")
        )
        deviation = hashlib.sha256(
            f"HC-011:{frozen['head']}:target-webview-bridge-not-executed".encode()
        ).hexdigest()
        return Evaluation(
            target_verdict="BLOCKED",
            blocked_kind="ACCESS",
            blocked_detail=(
                "An exact read-only PortfolioCommandCenter archive is available, "
                "but no qualified target webview-to-command-bridge executor is "
                "available for the actual Tauri IPC path."
                if archive_available
                else (
                    "No fidelity-proven PortfolioCommandCenter archive is available "
                    "for the target webview command-bridge case."
                )
            ),
            observations=[
                {
                    "browser_required": True,
                    "browser_mode": context.browser_mode,
                    "unsafe_fallback_refused": True,
                    "archive_available": archive_available,
                    "archive_sha256": archive.get("sha256"),
                    "target_code_executed": False,
                    "fixture_browser_evidence_substituted": False,
                }
            ],
            limitations=[
                "Browser qualification and successful target compilation cannot establish behavior of an unexercised Tauri webview command bridge."
            ],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
            subject_version=f"git:{frozen['head']}+deviations:{deviation}",
        )
    return Evaluation(
        target_verdict="BLOCKED",
        blocked_kind="ACCESS",
        blocked_detail="No browser or embedded-webview executor is implemented for this suite.",
        observations=[
            {
                "browser_required": True,
                "browser_mode": context.browser_mode,
                "unsafe_fallback_refused": True,
            }
        ],
        limitations=["No browser or embedded-webview behavior was executed."],
        positive_control="NOT_RUN",
        negative_control="NOT_RUN",
        containment_result="NOT_APPLICABLE",
        cleanup_result="NOT_APPLICABLE",
    )


def _sha256_file(path: Path) -> str:
    return hashlib.sha256(path.read_bytes()).hexdigest()


def _single_pcc_test_executable(source_root: Path) -> Path | None:
    candidates = sorted(
        candidate
        for candidate in (source_root / "target/debug/deps").glob("portfolio_command_center_lib-*")
        if candidate.is_file() and os.access(candidate, os.X_OK)
    )
    return candidates[0] if len(candidates) == 1 else None


def _write_fake_zsh(fake_bin: Path) -> Path:
    fake_bin.mkdir(parents=True, exist_ok=False, mode=0o700)
    fake = fake_bin / "zsh"
    fake.write_text(
        "\n".join(
            (
                "#!/bin/sh",
                "set -eu",
                ": \"${MHAI_HC012_FAKE_ZSH_LOG:?}\"",
                "{",
                "  printf 'fake_zsh_invoked=1\\n'",
                "  printf 'cwd=%s\\n' \"$(pwd)\"",
                "  printf 'argv='",
                "  for arg in \"$@\"; do printf '[%s]' \"$arg\"; done",
                "  printf '\\n'",
                "} >> \"$MHAI_HC012_FAKE_ZSH_LOG\"",
                "exec /bin/zsh \"$@\"",
                "",
            )
        ),
        encoding="utf-8",
    )
    fake.chmod(0o700)
    return fake


def _run_hc012_domain(
    *,
    domain_root: Path,
    executable: Path | None,
    use_hostile_path: bool,
    vulnerable_control: bool = False,
) -> dict[str, Any]:
    if domain_root.exists():
        shutil.rmtree(domain_root)
    domain_root.mkdir(parents=True, mode=0o700)
    fake_log = domain_root / "fake-zsh.log"
    fake = _write_fake_zsh(domain_root / "fake-bin")
    safe_path = "/bin:/usr/bin:/usr/local/bin"
    path = f"{fake.parent}:{safe_path}" if use_hostile_path else safe_path
    env = scrubbed_environment(
        domain_root,
        {
            "PATH": path,
            "MHAI_HC012_FAKE_ZSH_LOG": str(fake_log),
            "RUST_TEST_THREADS": "1",
        },
    )
    if vulnerable_control:
        argv = [
            "/usr/bin/env",
            "zsh",
            "-lc",
            "printf 'hc012 vulnerable control reached\\n'",
        ]
        cwd = domain_root
    else:
        if executable is None:
            raise FileNotFoundError("exact PortfolioCommandCenter test executable is unavailable")
        argv = [str(executable), PCC_HC012_TEST_NAME, "--exact", "--nocapture"]
        cwd = executable.parents[3]
    completed = run_argv(
        argv,
        cwd=cwd,
        environment=env,
        timeout_seconds=20,
        max_output_bytes=512 * 1024,
        apply_resource_limits=False,
    )
    fake_log_bytes = fake_log.read_bytes() if fake_log.exists() else b""
    payload = {
        "domain": domain_root.name,
        "argv_sha256": hashlib.sha256(json.dumps(argv, sort_keys=True).encode()).hexdigest(),
        "returncode": completed.returncode,
        "timed_out": completed.timed_out,
        "stdout_sha256": hashlib.sha256(completed.stdout).hexdigest(),
        "stderr_sha256": hashlib.sha256(completed.stderr).hexdigest(),
        "stdout_tail": completed.stdout.decode(errors="replace")[-400:],
        "stderr_tail": completed.stderr.decode(errors="replace")[-400:],
        "fake_zsh_path": str(fake),
        "fake_zsh_sha256": _sha256_file(fake),
        "fake_zsh_followed": bool(fake_log_bytes),
        "fake_zsh_log_sha256": hashlib.sha256(fake_log_bytes).hexdigest(),
        "fake_zsh_log_tail": fake_log_bytes.decode(errors="replace")[-400:],
        "path_mode": "hostile" if use_hostile_path else "safe-baseline",
        "home_confined": env["HOME"].startswith(str(domain_root.resolve())),
        "tmp_confined": env["TMPDIR"].startswith(str(domain_root.resolve())),
    }
    shutil.rmtree(domain_root)
    payload["cleanup_verified"] = not domain_root.exists()
    payload["cleanup_sha256"] = hashlib.sha256(
        json.dumps(
            {
                "domain": domain_root.name,
                "exists_after_cleanup": domain_root.exists(),
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    return payload


def _evaluate_hc_012_target(case: dict[str, Any], context: RunContext) -> Evaluation:
    frozen = context.frozen_target(case["case_id"])
    archive = frozen["archive"]
    archive_available = bool(archive.get("created") and archive.get("fidelity_proven"))
    archive_sha256 = archive.get("sha256")
    source_root = ROOT / f"work/isolated-targets/executors/pcc-{PCC_HC012_COMMIT}"
    lockfile = source_root / "src-tauri/Cargo.lock"
    executable = _single_pcc_test_executable(source_root)
    prerequisites = {
        "source_commit_matches": frozen["head"] == PCC_HC012_COMMIT,
        "archive_available": archive_available,
        "archive_sha256_matches": archive_sha256 == PCC_HC012_ARCHIVE_SHA256,
        "source_root_available": source_root.is_dir(),
        "lockfile_sha256_matches": lockfile.is_file()
        and _sha256_file(lockfile) == PCC_HC012_CARGO_LOCK_SHA256,
        "test_executable_available": executable is not None,
    }
    if not all(prerequisites.values()):
        deviation = hashlib.sha256(
            f"HC-012:{frozen['head']}:target-command-launch-prerequisite-missing".encode()
        ).hexdigest()
        return Evaluation(
            target_verdict="BLOCKED",
            blocked_kind="ACCESS",
            blocked_detail=(
                "The exact PortfolioCommandCenter HC-012 executor prerequisites are "
                "not all available under the program-owned archive boundary."
            ),
            observations=[
                {
                    "source_candidate_head": frozen["head"],
                    "source_candidate_tree": frozen["tree"],
                    "source_clean_at_epoch_open": frozen["clean"],
                    "ownership": frozen["ownership"],
                    "archive_sha256": archive_sha256,
                    "required_archive_sha256": PCC_HC012_ARCHIVE_SHA256,
                    "required_lockfile_sha256": PCC_HC012_CARGO_LOCK_SHA256,
                    "prerequisites": prerequisites,
                    "target_code_executed": False,
                    "target_repository_accessed_during_case": False,
                    "substitute_fixture_claimed": False,
                }
            ],
            limitations=[
                "No target command-launch behavior was executed because exact executor prerequisites were incomplete."
            ],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
            subject_version=f"git:{frozen['head']}+deviations:{deviation}",
        )

    assert executable is not None
    executable_sha256 = _sha256_file(executable)
    case_root = context.case_root / "hc012-path-poisoning"
    vulnerable = _run_hc012_domain(
        domain_root=case_root / "vulnerable-control",
        executable=None,
        use_hostile_path=True,
        vulnerable_control=True,
    )
    baseline = _run_hc012_domain(
        domain_root=case_root / "safe-baseline",
        executable=executable,
        use_hostile_path=False,
    )
    hostile = _run_hc012_domain(
        domain_root=case_root / "hostile-path",
        executable=executable,
        use_hostile_path=True,
    )
    positive_passed = (
        vulnerable["returncode"] == 0
        and vulnerable["fake_zsh_followed"]
        and vulnerable["cleanup_verified"]
    )
    negative_passed = (
        baseline["returncode"] == 0
        and not baseline["fake_zsh_followed"]
        and baseline["cleanup_verified"]
    )
    hostile_completed = hostile["returncode"] == 0 and not hostile["timed_out"]
    hostile_fake_followed = hostile["fake_zsh_followed"]
    if case_root.exists():
        shutil.rmtree(case_root)
    cleanup_passed = all(
        item["cleanup_verified"] for item in (vulnerable, baseline, hostile)
    ) and not case_root.exists()
    observations = [
        {
            "source_candidate_head": frozen["head"],
            "source_candidate_tree": frozen["tree"],
            "source_clean_at_epoch_open": frozen["clean"],
            "ownership": frozen["ownership"],
            "archive_path": archive.get("path"),
            "archive_sha256": archive_sha256,
            "archive_fidelity_proven": archive.get("fidelity_proven"),
            "lockfile_path": str(lockfile.relative_to(ROOT)),
            "lockfile_sha256": PCC_HC012_CARGO_LOCK_SHA256,
            "test_executable_path": str(executable.relative_to(ROOT)),
            "test_executable_sha256": executable_sha256,
            "test_name": PCC_HC012_TEST_NAME,
            "instrumentation": {
                "vulnerable_control": vulnerable,
                "safe_baseline": baseline,
                "hostile_path": hostile,
            },
            "target_code_executed": True,
            "target_repository_accessed_during_case": False,
            "substitute_fixture_claimed": False,
            "ambient_fake_zsh_followed_without_detection": hostile_fake_followed
            and hostile_completed,
            "containment_domains": [
                "vulnerable-control",
                "safe-baseline",
                "hostile-path",
            ],
            "cleanup_verified": cleanup_passed,
        }
    ]
    subject_deviation = hashlib.sha256(
        json.dumps(
            {
                "case_id": "HC-012",
                "executor_sha256": executable_sha256,
                "hostile_fake_zsh_followed": hostile_fake_followed,
                "test_name": PCC_HC012_TEST_NAME,
            },
            sort_keys=True,
        ).encode()
    ).hexdigest()
    if not positive_passed or not negative_passed or not cleanup_passed:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control="PASS" if positive_passed else "FAIL",
            negative_control="PASS" if negative_passed else "FAIL",
            containment_result="PASS",
            cleanup_result="PASS" if cleanup_passed else "FAIL",
            declared_result="ERROR",
            limitations=[
                "The HC-012 executor control matrix did not satisfy the vulnerable-control, safe-baseline, and cleanup oracles."
            ],
            subject_version=f"git:{PCC_HC012_COMMIT}+deviations:{subject_deviation}",
        )
    return Evaluation(
        target_verdict="FAIL" if hostile_fake_followed and hostile_completed else "PASS",
        observations=observations,
        positive_control="PASS",
        negative_control="PASS",
        containment_result="PASS",
        cleanup_result="PASS",
        limitations=[
            "This executes the archived PortfolioCommandCenter Rust command-spawn path via its compiled test harness; it does not exercise the separate Tauri webview IPC path required for HC-011."
        ],
        subject_version=f"git:{PCC_HC012_COMMIT}+deviations:{subject_deviation}",
    )


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    """Evaluate one HC case without exceeding its declared evidence ceiling."""

    case_id = str(case.get("case_id", ""))
    if case_id not in _SUPPORTED_CASES:
        raise ValueError(f"unsupported Host Confused Deputy case: {case_id or '<missing>'}")
    if case_id in _BROWSER_CASES:
        return _browser_refusal(case, context)
    if case_id == "HC-012":
        return _evaluate_hc_012_target(case, context)
    return _EVALUATORS[case_id]()
