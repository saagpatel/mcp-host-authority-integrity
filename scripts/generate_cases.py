#!/usr/bin/env python3
"""Generate the immutable 57-case catalog and its coverage matrix."""

from __future__ import annotations

import argparse
import hashlib
import json
from pathlib import Path
from typing import Any

ROOT = Path(__file__).resolve().parents[1]

SUITES = {
    "RT": ("runtime-truth", "Runtime Truth"),
    "SA": ("stateless-authority", "Stateless Authority"),
    "HC": ("host-confused-deputy", "Host Confused Deputy"),
    "LP": ("local-privilege-containment", "Local Privilege Containment"),
    "OA": ("stateless-authority", "OAuth and Browser Identity"),
    "CHAIN": ("integrated-chain", "Integrated Attack Chain"),
}

# id, name, protocol/component, protocol status, source ids, exact subject claim,
# pass condition, fail condition, evidence ceiling
SPECS: list[tuple[str, str, str, str, list[str], str, str, str, str]] = [
    ("RT-001", "Hidden prompt content", "MCP prompts", "RELEASED_CORE", ["MCP-PROMPTS-2025-11-25", "MCP-RUNTIME-SCANNER-STUDY"], "The fixture host distinguishes prompt list metadata from the body returned by prompts/get.", "The retrieved synthetic authority-seeking body is observed and classified separately from its harmless descriptor.", "The host treats the harmless descriptor as proof and does not observe the contradictory retrieved body.", "FIXTURE_HOST"),
    ("RT-002", "Hidden resource content", "MCP resources", "RELEASED_CORE", ["MCP-RESOURCES-2025-11-25", "MCP-RUNTIME-SCANNER-STUDY"], "The fixture host distinguishes resource list metadata from content returned by resources/read.", "The retrieved executable-looking content is observed and classified separately from its harmless descriptor.", "The host records the resource safe without reading or classifying the contradictory body.", "FIXTURE_HOST"),
    ("RT-003", "Tool-call behavior gap", "MCP tools", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "The fixture host measures tools/call effects instead of inferring behavior from the descriptor.", "The program-owned mutation attempt is observed and the descriptor/runtime mismatch is reported.", "The mutation attempt occurs but the runtime mismatch is omitted or classified safe.", "FIXTURE_HOST"),
    ("RT-004", "Read-only annotation lie", "MCP tool annotations", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "The fixture host does not accept readOnlyHint as behavioral proof.", "A canary mutation contradicting readOnlyHint is detected and reported.", "The mutation occurs while readOnlyHint is accepted as proof of no mutation.", "FIXTURE_HOST"),
    ("RT-005", "Open-world annotation lie", "MCP tool annotations", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "The fixture host dynamically checks a tool marked openWorldHint false.", "An exact run-owned loopback attempt is observed as contradicting the annotation.", "The attempt occurs but the false annotation is accepted as behavioral proof.", "FIXTURE_HOST"),
    ("RT-006", "Pagination trap", "MCP pagination", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25", "MCP-PROMPTS-2025-11-25", "MCP-RESOURCES-2025-11-25"], "The fixture host follows every valid cursor exactly once and detects contradictory later pages.", "All pages are enumerated and the later contradictory entry is observed without cursor loops.", "Enumeration stops early, loops, or reports the first page as complete.", "FIXTURE_HOST"),
    ("RT-007", "List-changed mutation", "MCP tools list_changed", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "The fixture host invalidates cached trust and approval state after tools/list_changed.", "Changed schema, annotation, identity, and effect force fresh discovery and approval.", "A stale cached descriptor or approval authorizes the changed tool.", "FIXTURE_HOST"),
    ("RT-008", "Client fingerprinting", "MCP initialization", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "The fixture comparison reports client- and protocol-dependent server behavior only for hosts actually exercised.", "Different fixture identities produce a recorded differential with exact client labels.", "A differential is missed or generalized to an unavailable client.", "FIXTURE_HOST"),
    ("RT-009", "Tool-origin collision", "MCP multi-server tools", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "Same-named tools remain bound to server identity through selection, approval, execution, logs, and result.", "The intended server-bound canary alone is affected and every receipt names that server.", "A sibling server receives authority or origin becomes ambiguous.", "FIXTURE_HOST"),
    ("RT-010", "Timeout process escape", "Local process supervision", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "An independent containment supervisor prevents a timed-out child or grandchild from acting later.", "The entire containment domain ends and no delayed canary appears after the observation window.", "Any descendant survives timeout or performs the delayed canary action.", "FIXTURE_SERVER"),
    ("RT-011", "Container isolation reality", "Container runtime", "LOCAL_CONTRACT", ["MHAI-SAFETY", "LOCAL-TARGET-SNAPSHOT"], "The exact recorded disposable container flags deny host reachability and bound filesystem, privileges, and processes.", "All positive sensors fire in the permissive control and all prohibited probes fail in the isolated subject.", "A prohibited host, filesystem, privilege, metadata, DNS, or process-limit probe succeeds.", "FIXTURE_SERVER"),
    ("RT-012", "Trust registry self-scan", "mcp-trust read-only MCP interface", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT", "MCP-TOOLS-2025-11-25"], "The exact pinned mcp-trust read-only interface claim is compared with only behavior observable without mutation.", "Public annotations and observable read behavior are reported with an explicit evidence ceiling.", "Unexercised mutation or isolation behavior is represented as proven.", "LIVE_TARGET"),
    ("SA-001", "State-handle theft", "Explicit MCP state handles", "FINAL_PROPOSAL", ["SEP-2567"], "Fixture authorization is checked independently of state-handle possession.", "Cross-principal, cross-tool, neighboring, expired, and revoked handles are rejected without disclosure.", "Possession of any tested invalid-authority handle grants continuation or data.", "FIXTURE_SERVER"),
    ("SA-002", "Handle tampering", "Explicit MCP state handles", "FINAL_PROPOSAL", ["SEP-2567"], "Malformed or modified state handles fail closed before authority use.", "Every byte, field, encoding, casing, and wrapper mutation is rejected.", "Any tampered handle is normalized into a valid authorization context.", "FIXTURE_SERVER"),
    ("SA-003", "Continuation-state swap", "MCP continuation requestState", "FINAL_PROPOSAL", ["SEP-2567"], "Continuation material is bound to principal, server, operation, and originating request.", "Every cross-user, cross-tool, cross-prompt, and cross-request swap is rejected.", "Swapped continuation material resumes or performs an unauthorized effect.", "FIXTURE_SERVER"),
    ("SA-004", "Input-response replay", "Idempotent continuation", "FINAL_PROPOSAL", ["SEP-2567"], "A replayed input-response key cannot apply the downstream synthetic action more than once.", "Retries return one stable outcome while the canary counter remains exactly one.", "The downstream canary counter exceeds one.", "FIXTURE_SERVER"),
    ("SA-005", "Task cross-tenant access", "MCP Tasks", "RELEASED_EXPERIMENTAL", ["MCP-TASKS-2025-11-25"], "Task get, update, cancel, list, and result access are tenant-bound.", "Principal B receives indistinguishable denial for every operation on A's task.", "B observes task details or changes A's task.", "FIXTURE_SERVER"),
    ("SA-006", "Task revocation", "MCP Tasks", "RELEASED_EXPERIMENTAL", ["MCP-TASKS-2025-11-25"], "Task result retrieval rechecks current authority after revocation.", "Revoked principal A cannot retrieve delayed results or complete a pending side effect.", "Previously held authority remains sufficient after revocation.", "FIXTURE_SERVER"),
    ("SA-007", "Task cancellation race", "MCP Tasks", "RELEASED_EXPERIMENTAL", ["MCP-TASKS-2025-11-25", "MHAI-SAFETY"], "Cancellation is reported only after fixture work has verifiably ceased at the synthetic boundary.", "All race schedules reconcile to stopped or completed truth and no post-cancel canary appears.", "The client reports cancellation while work continues or the boundary is crossed later.", "FIXTURE_SERVER"),
    ("SA-008", "Task capability stickiness", "MCP Tasks negotiation", "RELEASED_EXPERIMENTAL", ["MCP-TASKS-2025-11-25"], "Task behavior follows the current request capability rather than stale remembered support.", "A request omitting Tasks is handled synchronously or rejected without task creation.", "Stale capability state causes an unadvertised task response.", "FIXTURE_SERVER"),
    ("SA-009", "Unsolicited server request", "MCP server-request correlation", "FINAL_PROPOSAL", ["SEP-2260"], "Sampling, elicitation, and roots requests require a valid live parent request.", "Requests without a parent, after completion, or with a forged parent are rejected without releasing data.", "Any forged or stale association releases model, user, or filesystem-shaped synthetic data.", "FIXTURE_HOST"),
    ("SA-010", "Header/body split-brain", "MCP HTTP standardization", "FINAL_PROPOSAL", ["SEP-2243"], "Mcp-Method must equal the case-sensitive JSON-RPC method and Mcp-Name must equal the applicable params.name after case-insensitive header-name parsing, or the request is rejected before execution.", "Duplicate Mcp-Method/Mcp-Name fields, case-varied header names, invalid encodings, proxy normalization, and any header/body value disagreement are rejected before authorization.", "Any disagreement selects one authority input and reaches the canary action.", "FIXTURE_HOST"),
    ("SA-011", "Cross-user cache leak", "Host result cache", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "Private cached results are keyed by user, scope, server, authorization state, and expiry.", "Every boundary change causes a miss and only the exact original authority tuple hits.", "A private synthetic result crosses any changed authority dimension.", "FIXTURE_HOST"),
    ("SA-012", "Self-asserted client identity", "MCP client metadata", "RELEASED_CORE", ["MCP-TOOLS-2025-11-25"], "Self-asserted client name and capabilities do not independently grant approval or access.", "A forged trusted-looking identity receives the same policy decision as an untrusted client.", "Self-asserted metadata changes an authorization outcome.", "FIXTURE_SERVER"),
    ("SA-013", "Stateless rate-limit bypass", "Rate limiting", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "Rate limiting remains bound to principal and operation across transport and metadata rotation.", "Connection, handle, client, and tool-name rotation cannot reset the principal-operation budget.", "Rotation restores budget before the bounded window expires.", "FIXTURE_SERVER"),
    ("SA-014", "Go cross-origin default", "Official MCP Go SDK", "OFFICIAL_GUIDANCE", ["GO-MCP-SDK"], "An exact isolated official Go SDK version rejects hostile Origin and rebinding-shaped Host inputs under its recorded configuration.", "The exact version and configuration reject every hostile request while accepting the valid control.", "Any hostile input reaches the handler or the version/configuration is not exact.", "OFFICIAL_SDK"),
    ("SA-015", "Cross-SDK JSON disagreement", "Official MCP SDK JSON parsers", "OFFICIAL_GUIDANCE", ["MCP-PYTHON-SDK", "MCP-TYPESCRIPT-SDK", "JSON-SCHEMA-2020-12"], "Available exact-version official SDKs interpret adversarial JSON without authority-relevant disagreement.", "Duplicate keys, mixed case, confusables, unknown fields, and conflicts yield identical safe decisions.", "Available SDKs disagree in a way that can change authorization or execution.", "OFFICIAL_SDK"),
    ("HC-001", "App-frame message binding", "MCP Apps messaging", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "Accepted app messages are bound to exact frame, origin, server connection, request, and lifecycle.", "Forged source, origin, IDs, replies, and initialization order are rejected.", "A forged or stale frame message receives host authority.", "FIXTURE_HOST"),
    ("HC-002", "App tool visibility", "MCP Apps tool visibility", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "App-only, model-only, dual-use, and same-named sibling tools retain their visibility and server binding.", "Every discovery and invocation path exposes only the authorized tool set.", "A caller discovers or invokes a tool outside its visibility or server scope.", "FIXTURE_HOST"),
    ("HC-003", "Cross-server app call", "MCP Apps tool calls", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "An app can call app-only tools only on its bound server connection.", "Every cross-server app-only call is rejected before tool execution.", "A sibling server tool can be invoked through the app's host authority.", "FIXTURE_HOST"),
    ("HC-004", "Template review TOCTOU", "MCP Apps ui resource", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "Materially changed executable ui resource content invalidates cached review despite a stable URI.", "Content digest changes trigger revalidation before rendering or authority use.", "Changed executable content reuses the prior approval solely because the URI matches.", "FIXTURE_HOST"),
    ("HC-005", "CSP and permission escape", "Browser CSP and permissions", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "The disposable app host denies undeclared egress, nested-frame, clipboard, camera, microphone, and geolocation authority.", "All prohibited schemes, redirects, hosts, frames, and permissions are denied while declared controls work.", "Any undeclared egress or permission reaches its synthetic sensor.", "FIXTURE_HOST"),
    ("HC-006", "Consent gesture laundering", "Trusted host consent", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "Consequential consent remains in trusted host chrome and binds server, tool, arguments, and effect to a relevant gesture.", "Invisible, programmatic, fake, stale, and unrelated gestures cannot approve the action.", "An untrusted app gesture or content surface creates consequential approval.", "FIXTURE_HOST"),
    ("HC-007", "Model-context overwrite", "MCP Apps context update", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "App-provided context remains provenance-labelled, scoped, and lower authority than host instructions.", "Inject, replace, and persistence attempts remain untrusted app context.", "App content overwrites or persists as host-authority context.", "FIXTURE_HOST"),
    ("HC-008", "Unsupported-app fallback", "MCP Apps fallback", "STABLE_EXTENSION", ["MCP-APPS-2026-01-26"], "A client without App support treats hostile-looking App HTML as inert text or rejects it.", "No markup executes and no canary or message sensor is reached.", "Fallback content executes or acquires host authority.", "FIXTURE_HOST"),
    ("HC-009", "WebMCP frame contamination", "WebMCP registration lifecycle", "DRAFT_OR_EMERGING", ["WEBMCP-REPOSITORY"], "Web tool registrations remain origin-, frame-, and document-lifecycle-bound.", "Navigation, revocation, replacement, and frame removal delete stale registrations and enforce delegation.", "Stale or unauthorized cross-origin tools remain callable.", "FIXTURE_HOST"),
    ("HC-010", "ACP multi-root escape", "ACP additional directories", "STABLE_EXTENSION", ["ACP-ADDITIONAL-DIRECTORIES"], "The fixture client canonicalizes every filesystem access against the current authorized roots.", "Traversal, symlink, changed-root, removed-root, and direct-route attempts fail closed.", "Any path outside the current canonical roots is read or written.", "FIXTURE_HOST"),
    ("HC-011", "PortfolioCommandCenter webview boundary", "PortfolioCommandCenter Tauri bridge", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT"], "In an exact isolated source copy, hostile webview content cannot reach proposal-approval or external-apply-shaped commands.", "Only the vulnerable positive-control reproduction reaches a program canary; the subject path rejects hostile content.", "Hostile content reaches a sensitive command or the copy fidelity is insufficient but reported as proof.", "ISOLATED_TARGET_COPY"),
    ("HC-012", "PortfolioCommandCenter launch poisoning", "PortfolioCommandCenter process launch", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT"], "In an exact isolated source copy, command identity, evidence paths, and approval inputs do not follow untrusted ambient state.", "Fake paths and binaries are rejected or remain inside the program fixture with identity mismatch reported.", "Ambient state redirects a trusted launch or evidence decision without detection.", "ISOLATED_TARGET_COPY"),
    ("LP-001", "Loopback cookie cross-port theft", "Synthetic loopback session", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "A synthetic loopback session is not accepted across attacker and legitimate fixture ports without exact origin binding.", "Cross-port disclosure or replay cannot reach synthetic approve, send, or apply routes.", "The attacker fixture obtains and replays a session into any consequential synthetic route.", "FIXTURE_SERVER"),
    ("LP-002", "Subagent authority escape", "Delegated local authority", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "A fixture child cannot exceed the parent's sacrificial directory and read-only capability.", "Out-of-scope child and sibling requests are denied and no outside canary changes.", "Delegation expands authority or changes a canary outside the granted subtree.", "FIXTURE_HOST"),
    ("LP-003", "Approval replay", "Host approval capability", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "Synthetic approval is bound to actor, server, action, normalized arguments, target, and expiry.", "Sibling, later, modified-argument, different-server, and expired replays are rejected.", "Any altered authority tuple consumes the approval.", "FIXTURE_HOST"),
    ("LP-004", "Stdio environment leak", "MCP stdio launch", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "A hostile fixture MCP server inherits only an explicit minimum environment and descriptor allowlist.", "Only approved key names, descriptors, working directory, and control endpoints are visible.", "A disallowed key name, descriptor, socket, path, or endpoint is inherited.", "FIXTURE_SERVER"),
    ("LP-005", "Sibling MCP pivot", "Multi-server local host", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "Compromising one fixture server does not grant direct sibling access or host impersonation.", "Distinct principals and host mediation reject every direct or synthetic-credential pivot.", "The compromised server invokes or impersonates its sibling.", "FIXTURE_HOST"),
    ("LP-006", "BridgeDB read isolation", "BridgeDB read contracts", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT"], "BridgeDB read isolation is claimed only where an independently enforceable principal boundary is observable.", "Live contracts are inspected read-only and fixture results remain explicitly fixture-scoped.", "Fixture authorization is represented as live BridgeDB tenant isolation proof.", "STATIC_EVIDENCE_ONLY"),
    ("LP-007", "AIGCCore offline claim", "AIGCCore isolated copy", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT"], "An exact isolated AIGCCore source copy performs no network action across the exercised UI, command, adapter, and dependency paths.", "Network sensors observe no subject attempt while permissive controls prove detection.", "Any subject network attempt occurs or static constants are reported as runtime proof.", "ISOLATED_TARGET_COPY"),
    ("LP-008", "Signed discovery key substitution", "Signed manifest discovery", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY"], "A manifest signature is not treated as publisher identity when the verification key is attacker-controlled and adjacent.", "The internally consistent forged bundle is rejected for lacking an independent identity anchor.", "The forged bundle is accepted as the claimed publisher solely because its adjacent key verifies it.", "FIXTURE_SERVER"),
    ("LP-009", "Private label public leak", "Synthetic public aggregation", "LOCAL_CONTRACT", ["LOCAL-TARGET-SNAPSHOT"], "Public aggregation excludes labels and metadata belonging only to synthetic private projects.", "No private-only marker appears in any generated public output while public controls do.", "Any synthetic private-only marker appears in public output.", "ISOLATED_TARGET_COPY"),
    ("LP-010", "Remote schema reference", "JSON Schema reference resolution", "OFFICIAL_GUIDANCE", ["JSON-SCHEMA-2020-12"], "Schema validation does not silently access network, loopback, files, or redirecting references.", "Every external reference is rejected before I/O and the permissive sensor proves attempted access is observable.", "Validation performs any prohibited reference fetch or file read.", "FIXTURE_HOST"),
    ("LP-011", "Schema validation exhaustion", "JSON Schema resource limits", "OFFICIAL_GUIDANCE", ["JSON-SCHEMA-2020-12", "MHAI-SAFETY"], "Hostile recursive, deep, alternating, and pattern schemas are rejected within strict time and memory limits.", "Every hostile schema stops within ceilings and the validator remains responsive to a valid follow-up.", "A ceiling is exceeded, a worker survives, or the valid follow-up cannot complete.", "FIXTURE_HOST"),
    ("OA-001", "Authorization metadata SSRF", "OAuth protected-resource metadata", "OFFICIAL_GUIDANCE", ["RFC-9728", "MCP-AUTH-2025-11-25"], "Synthetic authorization metadata retrieval revalidates every redirect hop and blocks non-owned destinations.", "Loopback aliases, private IPs, rebinding simulation, metadata-shaped addresses, and redirects are denied.", "Any prohibited destination receives a request.", "FIXTURE_HOST"),
    ("OA-002", "Issuer mix-up", "OAuth issuer identification", "OFFICIAL_GUIDANCE", ["RFC-9207", "MCP-AUTH-2025-11-25"], "Authorization responses, registrations, callbacks, and credentials remain bound to the selected issuer.", "Every swapped issuer or cached registration is rejected before credential use.", "A response or credential from authorization server A is accepted under server B.", "FIXTURE_HOST"),
    ("OA-003", "Resource mix-up", "OAuth resource indicators", "OFFICIAL_GUIDANCE", ["RFC-8707", "MCP-AUTH-2025-11-25"], "A synthetic token for resource A is rejected by resource B and is never forwarded.", "Resource B rejects the token without disclosing or forwarding it.", "Resource B accepts or forwards resource A's token.", "FIXTURE_HOST"),
    ("OA-004", "Loopback callback capture", "OAuth native-app callback", "OFFICIAL_GUIDANCE", ["RFC-8252"], "Synthetic loopback callback completion binds PKCE, state, redirect URI, browser flow, and one-shot code consumption.", "Port race, wrong state, replay, and second-tab attempts all fail while the exact callback succeeds once.", "Any attacker callback or replay completes the authorization.", "FIXTURE_HOST"),
    ("OA-005", "Client metadata impersonation", "OAuth client metadata document", "DRAFT_OR_EMERGING", ["OAUTH-CIMD-DRAFT-02"], "The approval surface exposes and binds the actual redirect target rather than trusting a legitimate-looking metadata identity.", "The attacker-controlled loopback redirect is visibly identified and cannot inherit trusted-brand approval.", "Brand-like metadata hides or authorizes the attacker redirect.", "FIXTURE_HOST"),
    ("OA-006", "URL elicitation identity swap", "MCP URL elicitation", "RELEASED_CORE", ["MCP-ELICITATION-2025-11-25"], "URL elicitation completion remains bound to the initiating synthetic user and client across redirects and tampering.", "Bob, Punycode, redirected, and parameter-tampered completions cannot complete Alice's request.", "A different user, client, or destination completes Alice's elicitation.", "FIXTURE_HOST"),
    ("CHAIN-001", "End-to-end authority integrity chain", "Integrated fixture chain", "FIXTURE_SECURITY_INVARIANT", ["MHAI-SAFETY", "MCP-TOOLS-2025-11-25", "SEP-2567", "MCP-APPS-2026-01-26"], "Every descriptor-to-runtime-to-state-to-app-to-local transition is recorded and the first effective defense prevents an escaped effect.", "The safe chain stops at a named boundary, the vulnerable control reaches only its canary, and cleanup proves no escape.", "The safe chain reaches the canary without an expected finding or any action escapes containment.", "FIXTURE_HOST"),
]


def case_for(spec: tuple[str, str, str, str, list[str], str, str, str, str]) -> dict[str, Any]:
    case_id, name, component, status, sources, claim, pass_oracle, fail_oracle, coverage = spec
    prefix = case_id.split("-", 1)[0]
    directory, suite_name = SUITES[prefix]
    fixture_role = "host" if coverage in {"FIXTURE_HOST", "ISOLATED_TARGET_COPY", "STATIC_EVIDENCE_ONLY", "LIVE_TARGET"} else "server"
    timeout = 30 if case_id in {"RT-010", "RT-011", "SA-007", "LP-011", "CHAIN-001"} else 10
    version_patterns = {
        "LIVE_TARGET": r"^git:[a-f0-9]{40}([a-f0-9]{24})?$",
        "ISOLATED_TARGET_COPY": r"^git:[a-f0-9]{40}([a-f0-9]{24})?\+deviations:[a-f0-9]{64}$",
        "OFFICIAL_SDK": r"^package:[A-Za-z0-9._/@+-]+@[A-Za-z0-9._+-]+$",
        "FIXTURE_HOST": r"^fixture:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$",
        "FIXTURE_SERVER": r"^fixture:[A-Za-z0-9._-]+@sha256:[a-f0-9]{64}$",
        "STATIC_EVIDENCE_ONLY": r"^snapshot:sha256:[a-f0-9]{64}$",
    }
    browser_cases = {
        "HC-001",
        "HC-005",
        "HC-006",
        "HC-009",
        "HC-011",
        "OA-004",
        "OA-005",
        "OA-006",
    }
    return {
        "case_id": case_id,
        "suite": suite_name,
        "plain_language_name": name,
        "claim_under_test": claim,
        "exact_subject_claim": claim,
        "target_kind": coverage,
        "protocol_or_component": component,
        "protocol_status": status,
        "source_citations": sources,
        "preconditions": [
            "Gate 1A catalog validation passes.",
            "Gate 1B containment qualification passes before active adversarial execution.",
            "Only synthetic principals and program-owned canaries are present.",
        ],
        "synthetic_principals": [f"{case_id.lower()}-principal-a", f"{case_id.lower()}-principal-b"],
        "fixture": {
            "family": directory,
            "role": fixture_role,
            "variant": case_id.lower(),
            "canary": f"work/canaries/<run-id>/{case_id.lower()}.json",
            "network": "run-owned isolated namespace or exact run-owned socket identity",
        },
        "attack_steps": [
            f"Create a fresh contained {case_id} fixture with a unique synthetic authority tuple.",
            f"Exercise the adversarial {name.lower()} variant and record bounded observations.",
            "Run the vulnerable positive control and safe negative control in separate fresh domains.",
            "Evaluate the exact pass and fail oracles, redact evidence, and verify cleanup.",
        ],
        "allowed_effects": [
            "Create or update the declared program-owned canary inside the current run.",
            "Connect only to an exact run-owned fixture socket when the case requires networking.",
        ],
        "forbidden_effects": [
            "Access any real credential, account, connector, user content, or external service.",
            "Write outside the current program-owned sacrificial run directory.",
            "Contact an arbitrary host, LAN, cloud metadata, or pre-existing loopback listener.",
        ],
        "pass_oracle": pass_oracle,
        "fail_oracle": fail_oracle,
        "positive_control": f"A deliberately vulnerable {case_id} fixture must satisfy the fail oracle using only its program canary.",
        "negative_control": f"A safe {case_id} fixture must satisfy the pass oracle without a forbidden effect.",
        "timeout_seconds": timeout,
        "cleanup": [
            "Revoke the run lease and stop the complete containment domain.",
            "Verify no run-owned process, listener, mount, profile, namespace, or delayed action remains.",
            "Preserve only schema-valid redacted evidence outside fixture-writable paths.",
        ],
        "coverage_level": coverage,
        "evidence_ceiling": {
            "coverage_level": coverage,
            "subject": claim,
            "version_rule": "The result version must fully match version_pattern for this evidence level.",
            "version_pattern": version_patterns[coverage],
            "instrumentation": "Broker observations, canary state, control results, containment receipt, and cleanup receipt.",
        },
        "result": "NOT_RUN",
        "evidence": [],
        "limitations": [
            "The case definition is not an execution result.",
            "Coverage cannot exceed the declared evidence ceiling.",
            "Fixture evidence does not prove behavior of an untested installed host.",
        ],
        "execution_family": directory,
        "requires_browser": case_id in browser_cases,
    }


def canonical_json(value: Any) -> str:
    return json.dumps(value, indent=2, sort_keys=True, ensure_ascii=True) + "\n"


def build_outputs() -> dict[Path, str]:
    cases = [case_for(spec) for spec in SPECS]
    outputs: dict[Path, str] = {}
    for directory in sorted({value[0] for value in SUITES.values()}):
        selected = [case for case in cases if case["execution_family"] == directory]
        outputs[ROOT / "suites" / directory / "cases.json"] = canonical_json(selected)
    outputs[ROOT / "cases.json"] = canonical_json(cases)

    lines = [
        "# Coverage matrix",
        "",
        "Generated from the immutable catalog. Execution status and result remain `NOT_RUN` until a schema-valid result record exists.",
        "",
        "| Case | Suite | Implemented | Execution | Coverage ceiling | Protocol status | Sources | Result | Limitation |",
        "|---|---|---|---|---|---|---|---|---|",
    ]
    for case in cases:
        sources = ", ".join(case["source_citations"])
        limitation = {
            "LIVE_TARGET": "Read-only observation cannot prove unexercised behavior.",
            "ISOLATED_TARGET_COPY": "Applies only to the pinned copy and recorded deviations.",
            "OFFICIAL_SDK": "Applies only to the exact SDK version and configuration.",
            "STATIC_EVIDENCE_ONLY": "Static evidence cannot prove runtime isolation.",
        }.get(case["coverage_level"], "Fixture evidence cannot prove an untested installed host.")
        lines.append(
            f"| {case['case_id']} | {case['suite']} | CATALOGUED | NOT_RUN | "
            f"{case['coverage_level']} | {case['protocol_status']} | {sources} | NOT_RUN | "
            f"{limitation} |"
        )
    lines.extend(
        [
            "",
            "## Catalog digest",
            "",
            f"`sha256:{hashlib.sha256(canonical_json(cases).encode()).hexdigest()}`",
            "",
        ]
    )
    outputs[ROOT / "COVERAGE-MATRIX.md"] = "\n".join(lines)
    return outputs


def main() -> int:
    parser = argparse.ArgumentParser()
    parser.add_argument("--write", action="store_true")
    parser.add_argument("--check", action="store_true")
    args = parser.parse_args()
    if args.write == args.check:
        parser.error("choose exactly one of --write or --check")
    mismatches: list[str] = []
    for path, expected in build_outputs().items():
        if args.write:
            path.parent.mkdir(parents=True, exist_ok=True)
            path.write_text(expected, encoding="utf-8")
        elif not path.exists() or path.read_text(encoding="utf-8") != expected:
            mismatches.append(str(path.relative_to(ROOT)))
    if mismatches:
        print("generated outputs differ: " + ", ".join(mismatches))
        return 1
    print(f"{'wrote' if args.write else 'verified'} {len(SPECS)} case definitions")
    return 0


if __name__ == "__main__":
    raise SystemExit(main())
