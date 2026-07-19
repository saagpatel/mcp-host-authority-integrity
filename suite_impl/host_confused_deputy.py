"""Deterministic, synthetic Host Confused Deputy suite oracles.

The non-browser cases in this module are pure in-memory models. They exercise a
deliberately vulnerable positive control and a fail-closed negative control
without opening sockets, reading target repositories, or touching a filesystem.
Browser-dependent cases route through the shared browser policy and never fall
back to simulated browser evidence.
"""

from __future__ import annotations

import hashlib
import posixpath
from collections.abc import Callable
from dataclasses import dataclass
from typing import Any

from harness.execution import Evaluation, RunContext, browser_block

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


def evaluate(case: dict[str, Any], context: RunContext) -> Evaluation:
    """Evaluate one HC case without exceeding its declared evidence ceiling."""

    case_id = str(case.get("case_id", ""))
    if case_id not in _SUPPORTED_CASES:
        raise ValueError(f"unsupported Host Confused Deputy case: {case_id or '<missing>'}")
    if case_id in _BROWSER_CASES:
        return _browser_refusal(case, context)
    if case_id == "HC-012":
        return Evaluation(
            target_verdict="BLOCKED",
            blocked_kind="ACCESS",
            blocked_detail=(
                "The pinned isolated PortfolioCommandCenter source drifted and no approved "
                "program-owned copy exists; target access and substitute reproduction are refused."
            ),
            observations=[
                {
                    "isolated_copy_available": False,
                    "target_repository_accessed": False,
                    "substitute_fixture_claimed": False,
                }
            ],
            limitations=[
                "No target source was read, copied, built, or executed for this evaluation."
            ],
            positive_control="NOT_RUN",
            negative_control="NOT_RUN",
            containment_result="NOT_APPLICABLE",
            cleanup_result="NOT_APPLICABLE",
        )
    return _EVALUATORS[case_id]()
