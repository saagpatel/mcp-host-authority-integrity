"""Browser-executed fixture-host controls for browser-required cases."""

from __future__ import annotations

from dataclasses import dataclass
from typing import Any

from harness.browser_runtime import BrowserSession, browser_html
from harness.execution import Evaluation, RunContext
from suite_impl.common import ScenarioDecision, controlled_evaluation


@dataclass(frozen=True)
class BrowserScenario:
    attacks: tuple[str, ...]
    vulnerable_script: str
    safe_script: str
    safe_reason: str
    vulnerable_csp: str | None = None
    safe_csp: str | None = None
    limitations: tuple[str, ...] = ()


def _string_list(payload: dict[str, Any], key: str) -> list[str] | None:
    value = payload.get(key)
    if not isinstance(value, list) or not all(isinstance(item, str) for item in value):
        return None
    return value


def _launch_evidence(role: str, launch: Any) -> dict[str, Any]:
    return {
        "role": role,
        "payload": launch.payload,
        "launcher": launch.evidence(),
    }


def _evaluate_scenario(
    case: dict[str, Any],
    context: RunContext,
    scenario: BrowserScenario,
) -> Evaluation:
    positive_root = context.case_root / "browser-positive"
    negative_root = context.case_root / "browser-negative"
    with BrowserSession(positive_root) as session:
        positive = session.run_html(
            browser_html(
                scenario.vulnerable_script,
                csp=scenario.vulnerable_csp,
            )
        )
    with BrowserSession(negative_root) as session:
        negative = session.run_html(
            browser_html(
                scenario.safe_script,
                csp=scenario.safe_csp,
            )
        )
    cleanup_verified = not positive_root.exists() and not negative_root.exists()
    vulnerable_accepts = _string_list(positive.payload, "accepted_variants")
    safe_accepts = _string_list(negative.payload, "accepted_variants")
    legitimate_control = negative.payload.get("legitimate_control")
    structure_valid = (
        vulnerable_accepts is not None
        and safe_accepts is not None
        and len(vulnerable_accepts) == len(set(vulnerable_accepts))
        and len(safe_accepts) == len(set(safe_accepts))
        and legitimate_control is True
        and cleanup_verified
    )
    observations = [
        {
            "kind": "browser-fixture-controls",
            "case_id": case["case_id"],
            "browser_mode": context.browser_mode,
            "separate_fresh_profiles": True,
            "profile_cleanup_verified": cleanup_verified,
            "positive": _launch_evidence("deliberately-vulnerable", positive),
            "negative": _launch_evidence("safe-subject", negative),
        }
    ]
    if not structure_valid or vulnerable_accepts is None or safe_accepts is None:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control="FAIL",
            negative_control="FAIL",
            declared_result="ERROR",
            limitations=[
                *scenario.limitations,
                "A browser fixture control did not emit the exact bounded result shape.",
            ],
        )

    attacks = list(scenario.attacks)
    vulnerable_for_control = (
        vulnerable_accepts
        if sorted(vulnerable_accepts) == sorted(attacks)
        else []
    )
    safe_decisions = [
        ScenarioDecision(variant in safe_accepts, scenario.safe_reason)
        for variant in attacks
    ]
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=attacks,
        safe_decisions=safe_decisions,
        vulnerable_accepts=vulnerable_for_control,
        observations=observations,
        limitations=[
            *scenario.limitations,
            "This is browser-executed fixture-host evidence, not proof about an installed host.",
        ],
    )
    if not cleanup_verified:
        evaluation.cleanup_result = "FAIL"
    return evaluation


_HC_001 = BrowserScenario(
    attacks=(
        "forged-source",
        "forged-origin",
        "forged-server-connection",
        "forged-request-id",
        "stale-lifecycle",
        "reply-before-initialize",
    ),
    safe_reason=(
        "the browser host binds source window, origin, server connection, request, "
        "lifecycle, and initialization state"
    ),
    vulnerable_script=r"""
const attacks = [
  {name: "forged-source", source: null, origin: "https://app.fixture.invalid", server: "server-a", request: "request-a", lifecycle: "document-a", initialized: true},
  {name: "forged-origin", source: window, origin: "https://attacker.fixture.invalid", server: "server-a", request: "request-a", lifecycle: "document-a", initialized: true},
  {name: "forged-server-connection", source: window, origin: "https://app.fixture.invalid", server: "server-b", request: "request-a", lifecycle: "document-a", initialized: true},
  {name: "forged-request-id", source: window, origin: "https://app.fixture.invalid", server: "server-a", request: "request-b", lifecycle: "document-a", initialized: true},
  {name: "stale-lifecycle", source: window, origin: "https://app.fixture.invalid", server: "server-a", request: "request-a", lifecycle: "document-old", initialized: true},
  {name: "reply-before-initialize", source: window, origin: "https://app.fixture.invalid", server: "server-a", request: "request-a", lifecycle: "document-a", initialized: false}
];
const accepted = [];
window.addEventListener("message", (event) => {
  if (event.data && event.data.type === "tool-result" && event.data.variant !== "legitimate-control") {
    accepted.push(event.data.variant);
  }
});
for (const attack of attacks) {
  window.dispatchEvent(new MessageEvent("message", {
    source: attack.source,
    origin: attack.origin,
    data: {
      type: "tool-result",
      variant: attack.name,
      server: attack.server,
      request: attack.request,
      lifecycle: attack.lifecycle,
      initialized: attack.initialized
    }
  }));
}
window.dispatchEvent(new MessageEvent("message", {
  source: window,
  origin: "https://app.fixture.invalid",
  data: {type: "tool-result", variant: "legitimate-control"}
}));
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: true,
  browser_message_events_dispatched: attacks.length + 1
});
""",
    safe_script=r"""
const expected = {
  source: window,
  origin: "https://app.fixture.invalid",
  server: "server-a",
  request: "request-a",
  lifecycle: "document-a"
};
const attacks = [
  {name: "forged-source", source: null, origin: expected.origin, server: expected.server, request: expected.request, lifecycle: expected.lifecycle, initialized: true},
  {name: "forged-origin", source: window, origin: "https://attacker.fixture.invalid", server: expected.server, request: expected.request, lifecycle: expected.lifecycle, initialized: true},
  {name: "forged-server-connection", source: window, origin: expected.origin, server: "server-b", request: expected.request, lifecycle: expected.lifecycle, initialized: true},
  {name: "forged-request-id", source: window, origin: expected.origin, server: expected.server, request: "request-b", lifecycle: expected.lifecycle, initialized: true},
  {name: "stale-lifecycle", source: window, origin: expected.origin, server: expected.server, request: expected.request, lifecycle: "document-old", initialized: true},
  {name: "reply-before-initialize", source: window, origin: expected.origin, server: expected.server, request: expected.request, lifecycle: expected.lifecycle, initialized: false}
];
const accepted = [];
let legitimate = false;
window.addEventListener("message", (event) => {
  const data = event.data || {};
  const allowed = (
    event.source === expected.source &&
    event.origin === expected.origin &&
    data.server === expected.server &&
    data.request === expected.request &&
    data.lifecycle === expected.lifecycle &&
    data.initialized === true
  );
  if (allowed && data.variant === "legitimate-control") legitimate = true;
  if (allowed && data.variant !== "legitimate-control") accepted.push(data.variant);
});
for (const attack of attacks) {
  window.dispatchEvent(new MessageEvent("message", {
    source: attack.source,
    origin: attack.origin,
    data: {
      type: "tool-result",
      variant: attack.name,
      server: attack.server,
      request: attack.request,
      lifecycle: attack.lifecycle,
      initialized: attack.initialized
    }
  }));
}
window.dispatchEvent(new MessageEvent("message", {
  source: window,
  origin: expected.origin,
  data: {
    type: "tool-result",
    variant: "legitimate-control",
    server: expected.server,
    request: expected.request,
    lifecycle: expected.lifecycle,
    initialized: true
  }
}));
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate,
  exact_event_source_compared: true,
  exact_origin_compared: true
});
""",
)


_HC_005 = BrowserScenario(
    attacks=(
        "undeclared-egress",
        "redirect-egress",
        "nested-frame",
        "clipboard",
        "camera",
        "microphone",
        "geolocation",
    ),
    safe_reason="the host CSP and permission policy rejects undeclared browser authority",
    vulnerable_csp=(
        "default-src data:; script-src 'unsafe-inline'; frame-src data:; "
        "connect-src http: https:; img-src data:"
    ),
    safe_csp=(
        "default-src 'none'; script-src 'unsafe-inline'; frame-src 'none'; "
        "connect-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
    vulnerable_script=r"""
const attacks = [
  "undeclared-egress", "redirect-egress", "nested-frame", "clipboard",
  "camera", "microphone", "geolocation"
];
const frame = document.createElement("iframe");
frame.src = "data:text/html,synthetic-frame";
document.body.appendChild(frame);
mhaiFinish({
  accepted_variants: attacks,
  legitimate_control: true,
  synthetic_sensor_events: attacks,
  nested_frame_created: frame.isConnected
});
""",
    safe_script=r"""
const requests = [
  {name: "undeclared-egress", kind: "egress", url: "https://attacker.fixture.invalid/x"},
  {name: "redirect-egress", kind: "redirect", url: "https://attacker.fixture.invalid/r"},
  {name: "nested-frame", kind: "frame", url: "data:text/html,frame"},
  {name: "clipboard", kind: "permission", permission: "clipboard"},
  {name: "camera", kind: "permission", permission: "camera"},
  {name: "microphone", kind: "permission", permission: "microphone"},
  {name: "geolocation", kind: "permission", permission: "geolocation"}
];
const authorize = (request) => request.kind === "render-local" && request.url.startsWith("data:");
const accepted = requests.filter(authorize).map((request) => request.name);
const legitimate = authorize({kind: "render-local", url: "data:text/plain,declared-control"});
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate,
  csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]').content,
  permissions_policy_api_present: Boolean(document.permissionsPolicy || document.featurePolicy),
  prohibited_dom_effects_created: 0
});
""",
)


_HC_006 = BrowserScenario(
    attacks=(
        "invisible-click",
        "programmatic-click",
        "fake-pointer-event",
        "stale-gesture",
        "unrelated-gesture",
    ),
    safe_reason=(
        "only trusted host chrome may bind a recent, visible, relevant gesture "
        "to the exact consequential action"
    ),
    vulnerable_script=r"""
const attacks = ["invisible-click", "programmatic-click", "fake-pointer-event", "stale-gesture", "unrelated-gesture"];
const button = document.createElement("button");
document.body.appendChild(button);
const accepted = [];
const trustedStates = [];
button.addEventListener("click", (event) => {
  accepted.push(button.dataset.variant);
  trustedStates.push(event.isTrusted);
});
for (const variant of attacks) {
  button.dataset.variant = variant;
  button.hidden = variant === "invisible-click";
  if (variant === "fake-pointer-event") {
    button.dispatchEvent(new MouseEvent("click", {bubbles: true}));
  } else {
    button.click();
  }
}
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: true,
  browser_event_is_trusted_values: trustedStates
});
""",
    safe_script=r"""
const attacks = ["invisible-click", "programmatic-click", "fake-pointer-event", "stale-gesture", "unrelated-gesture"];
const button = document.createElement("button");
document.body.appendChild(button);
const accepted = [];
const trustedStates = [];
const gestureMetadata = {
  "invisible-click": {age: 10, relevant: true},
  "programmatic-click": {age: 10, relevant: true},
  "fake-pointer-event": {age: 10, relevant: true},
  "stale-gesture": {age: 5000, relevant: true},
  "unrelated-gesture": {age: 10, relevant: false}
};
button.addEventListener("click", (event) => {
  const variant = button.dataset.variant;
  const metadata = gestureMetadata[variant];
  trustedStates.push(event.isTrusted);
  if (event.isTrusted && !button.hidden && metadata.age <= 500 && metadata.relevant) {
    accepted.push(variant);
  }
});
for (const variant of attacks) {
  button.dataset.variant = variant;
  button.hidden = variant === "invisible-click";
  if (variant === "fake-pointer-event") {
    button.dispatchEvent(new MouseEvent("click", {bubbles: true}));
  } else {
    button.click();
  }
}
const trustedHostApprove = (gesture) => (
  gesture.source === "trusted-host-chrome" &&
  gesture.age <= 500 &&
  gesture.visible &&
  gesture.server === "server-a" &&
  gesture.tool === "consequential-tool" &&
  gesture.argumentsDigest === "args-a"
);
const legitimate = trustedHostApprove({
  source: "trusted-host-chrome",
  age: 20,
  visible: true,
  server: "server-a",
  tool: "consequential-tool",
  argumentsDigest: "args-a"
});
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate,
  programmatic_browser_events_all_untrusted: trustedStates.every((value) => value === false),
  trusted_host_chrome_binding_checked: true
});
""",
)


_HC_009 = BrowserScenario(
    attacks=(
        "cross-origin-registration",
        "sibling-frame-call",
        "stale-after-navigation",
        "stale-after-replacement",
        "stale-after-frame-removal",
        "delegation-missing",
    ),
    safe_reason=(
        "tool registrations are bound to the exact origin, frame, document lifecycle, "
        "and explicit delegation"
    ),
    vulnerable_script=r"""
const attacks = [
  "cross-origin-registration", "sibling-frame-call", "stale-after-navigation",
  "stale-after-replacement", "stale-after-frame-removal", "delegation-missing"
];
const container = document.createElement("div");
document.body.appendChild(container);
for (const variant of attacks) {
  const frame = document.createElement("iframe");
  frame.dataset.variant = variant;
  container.appendChild(frame);
  if (variant === "stale-after-frame-removal") frame.remove();
}
mhaiFinish({
  accepted_variants: attacks,
  legitimate_control: true,
  registry_key: "tool-name-only",
  dom_lifecycle_mutations_exercised: true
});
""",
    safe_script=r"""
const accepted = [];
const container = document.createElement("div");
document.body.appendChild(container);
const makeFrame = (origin, documentId) => {
  const frame = document.createElement("iframe");
  frame.dataset.origin = origin;
  frame.dataset.documentId = documentId;
  container.appendChild(frame);
  return frame;
};
const register = (frame, delegated = true) => ({
  frame,
  origin: frame.dataset.origin,
  documentId: frame.dataset.documentId,
  delegated
});
const callable = (registration, frame, origin, delegated = true) => (
  registration.frame === frame &&
  frame.isConnected &&
  registration.origin === origin &&
  frame.dataset.origin === origin &&
  registration.documentId === frame.dataset.documentId &&
  registration.delegated &&
  delegated
);

let frame = makeFrame("https://app.fixture.invalid", "doc-cross");
let registration = register(frame);
if (callable(registration, frame, "https://attacker.fixture.invalid")) accepted.push("cross-origin-registration");
frame.remove();

frame = makeFrame("https://app.fixture.invalid", "doc-sibling");
const sibling = makeFrame("https://app.fixture.invalid", "doc-sibling-2");
registration = register(frame);
if (callable(registration, sibling, sibling.dataset.origin)) accepted.push("sibling-frame-call");
frame.remove();
sibling.remove();

frame = makeFrame("https://app.fixture.invalid", "doc-before-navigation");
registration = register(frame);
frame.dataset.documentId = "doc-after-navigation";
if (callable(registration, frame, frame.dataset.origin)) accepted.push("stale-after-navigation");
frame.remove();

frame = makeFrame("https://app.fixture.invalid", "doc-replacement");
registration = register(frame);
const replacement = makeFrame("https://app.fixture.invalid", "doc-replacement");
frame.replaceWith(replacement);
if (callable(registration, replacement, replacement.dataset.origin)) accepted.push("stale-after-replacement");
replacement.remove();

frame = makeFrame("https://app.fixture.invalid", "doc-removal");
registration = register(frame);
frame.remove();
if (callable(registration, frame, frame.dataset.origin)) accepted.push("stale-after-frame-removal");

frame = makeFrame("https://app.fixture.invalid", "doc-delegation");
registration = register(frame, false);
if (callable(registration, frame, frame.dataset.origin, false)) accepted.push("delegation-missing");
frame.remove();

frame = makeFrame("https://app.fixture.invalid", "doc-legitimate");
registration = register(frame, true);
const legitimate = callable(registration, frame, frame.dataset.origin, true);
frame.remove();
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate,
  exact_frame_identity_checked: true,
  disconnected_frames_rejected: true
});
""",
)


_OA_004 = BrowserScenario(
    attacks=(
        "port-race",
        "wrong-state",
        "pkce-swap",
        "redirect-uri-swap",
        "second-tab",
        "code-replay",
    ),
    safe_reason=(
        "completion binds the exact loopback redirect, state, PKCE verifier, browser "
        "flow identity, and one-shot code use"
    ),
    limitations=(
        "The loopback authority is browser-executed URL-routing logic; the browser "
        "network boundary remains deny-all and exposes no live callback listener.",
    ),
    vulnerable_script=r"""
const attacks = ["port-race", "wrong-state", "pkce-swap", "redirect-uri-swap", "second-tab", "code-replay"];
const accepted = [];
const complete = (callback) => Boolean(new URL(callback.url).searchParams.get("code"));
for (const variant of attacks) {
  const callback = {url: "http://127.0.0.1:49152/callback?code=synthetic-code", variant};
  if (complete(callback)) accepted.push(variant);
}
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: complete({url: "http://127.0.0.1:49152/callback?code=legitimate"}),
  browser_url_parser_used: true
});
""",
    safe_script=r"""
const attacks = ["port-race", "wrong-state", "pkce-swap", "redirect-uri-swap", "second-tab", "code-replay"];
const newFlow = () => ({
  redirect: "http://127.0.0.1:49152/callback",
  state: "state-a",
  verifier: "verifier-a",
  browserFlow: "tab-a",
  consumed: new Set()
});
const complete = (flow, callback) => {
  const url = new URL(callback.url);
  const redirect = `${url.origin}${url.pathname}`;
  const code = url.searchParams.get("code");
  if (
    redirect !== flow.redirect ||
    url.searchParams.get("state") !== flow.state ||
    callback.verifier !== flow.verifier ||
    callback.browserFlow !== flow.browserFlow ||
    !code ||
    flow.consumed.has(code)
  ) return false;
  flow.consumed.add(code);
  return true;
};
const accepted = [];
for (const variant of attacks) {
  const flow = newFlow();
  let callback = {
    url: "http://127.0.0.1:49152/callback?code=code-a&state=state-a",
    verifier: "verifier-a",
    browserFlow: "tab-a"
  };
  if (variant === "port-race") callback.url = "http://127.0.0.1:49153/callback?code=code-a&state=state-a";
  if (variant === "wrong-state") callback.url = "http://127.0.0.1:49152/callback?code=code-a&state=state-b";
  if (variant === "pkce-swap") callback.verifier = "verifier-b";
  if (variant === "redirect-uri-swap") callback.url = "http://127.0.0.1:49152/other?code=code-a&state=state-a";
  if (variant === "second-tab") callback.browserFlow = "tab-b";
  if (variant === "code-replay") {
    complete(flow, callback);
  }
  if (complete(flow, callback)) accepted.push(variant);
}
const legitimateFlow = newFlow();
const legitimateCallback = {
  url: "http://127.0.0.1:49152/callback?code=legitimate&state=state-a",
  verifier: "verifier-a",
  browserFlow: "tab-a"
};
const legitimate = complete(legitimateFlow, legitimateCallback);
const replayRejected = !complete(legitimateFlow, legitimateCallback);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate && replayRejected,
  exact_loopback_port_compared: true,
  one_shot_code_consumption: replayRejected
});
""",
)


_OA_005 = BrowserScenario(
    attacks=(
        "trusted-brand-loopback-redirect",
        "logo-confusion",
        "unicode-brand",
        "metadata-redirect-mismatch",
        "redirect-after-approval",
    ),
    safe_reason=(
        "the approval surface displays and binds the actual redirect identity "
        "instead of trusting brand-like metadata"
    ),
    vulnerable_script=r"""
const attacks = [
  "trusted-brand-loopback-redirect", "logo-confusion", "unicode-brand",
  "metadata-redirect-mismatch", "redirect-after-approval"
];
const heading = document.createElement("h1");
heading.textContent = "Trusted Example Client";
document.body.appendChild(heading);
mhaiFinish({
  accepted_variants: attacks,
  legitimate_control: true,
  displayed_identity: heading.textContent,
  redirect_displayed: false
});
""",
    safe_script=r"""
const attacks = [
  {name: "trusted-brand-loopback-redirect", redirect: "http://127.0.0.1:62222/callback", brand: "Trusted Example Client"},
  {name: "logo-confusion", redirect: "http://localhost:63333/callback", brand: "Trusted Example Client"},
  {name: "unicode-brand", redirect: "http://127.0.0.1:64444/callback", brand: "Truѕted Example Client"},
  {name: "metadata-redirect-mismatch", redirect: "https://attacker.fixture.invalid/callback", brand: "Trusted Example Client"},
  {name: "redirect-after-approval", redirect: "https://redirected.fixture.invalid/callback", brand: "Trusted Example Client"}
];
const expectedRedirect = "https://client.fixture.invalid/callback";
const approval = document.createElement("section");
const redirectNode = document.createElement("code");
redirectNode.id = "actual-redirect";
redirectNode.textContent = expectedRedirect;
approval.appendChild(redirectNode);
document.body.appendChild(approval);
const authorize = (candidate, boundRedirect) => (
  new URL(candidate.redirect).href === new URL(boundRedirect).href &&
  redirectNode.textContent === boundRedirect
);
const accepted = attacks.filter((attack) => authorize(attack, expectedRedirect)).map((attack) => attack.name);
const legitimate = authorize({redirect: expectedRedirect}, expectedRedirect);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate,
  displayed_redirect: redirectNode.textContent,
  metadata_brand_used_for_authority: false
});
""",
)


_OA_006 = BrowserScenario(
    attacks=(
        "bob-completes-alice",
        "client-swap",
        "punycode-destination",
        "redirected-destination",
        "parameter-tamper",
        "completion-replay",
    ),
    safe_reason=(
        "completion binds initiating user, client, destination, request parameters, "
        "and one-shot lifecycle"
    ),
    vulnerable_script=r"""
const attacks = [
  "bob-completes-alice", "client-swap", "punycode-destination",
  "redirected-destination", "parameter-tamper", "completion-replay"
];
const anchor = document.createElement("a");
anchor.href = "https://alice.fixture.invalid/complete?request=request-a";
document.body.appendChild(anchor);
mhaiFinish({
  accepted_variants: attacks,
  legitimate_control: Boolean(new URL(anchor.href).searchParams.get("request")),
  browser_anchor_normalization_used: true
});
""",
    safe_script=r"""
const newFlow = () => ({
  user: "alice",
  client: "client-a",
  destination: new URL("https://alice.fixture.invalid/complete").href,
  request: "request-a",
  parameterDigest: "params-a",
  consumed: false
});
const complete = (flow, candidate) => {
  const destination = new URL(candidate.destination).href;
  if (
    flow.consumed ||
    candidate.user !== flow.user ||
    candidate.client !== flow.client ||
    destination !== flow.destination ||
    candidate.request !== flow.request ||
    candidate.parameterDigest !== flow.parameterDigest
  ) return false;
  flow.consumed = true;
  return true;
};
const base = {
  user: "alice",
  client: "client-a",
  destination: "https://alice.fixture.invalid/complete",
  request: "request-a",
  parameterDigest: "params-a"
};
const variants = [
  {name: "bob-completes-alice", patch: {user: "bob"}},
  {name: "client-swap", patch: {client: "client-b"}},
  {name: "punycode-destination", patch: {destination: "https://xn--lice-43d.fixture.invalid/complete"}},
  {name: "redirected-destination", patch: {destination: "https://redirected.fixture.invalid/complete"}},
  {name: "parameter-tamper", patch: {parameterDigest: "params-b"}},
  {name: "completion-replay", patch: {}}
];
const accepted = [];
for (const variant of variants) {
  const flow = newFlow();
  const candidate = {...base, ...variant.patch};
  if (variant.name === "completion-replay") complete(flow, candidate);
  if (complete(flow, candidate)) accepted.push(variant.name);
}
const legitimateFlow = newFlow();
const legitimate = complete(legitimateFlow, base);
const replayRejected = !complete(legitimateFlow, base);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: legitimate && replayRejected,
  normalized_destination_compared: true,
  replay_rejected: replayRejected
});
""",
)


_HC_SCENARIOS = {
    "HC-001": _HC_001,
    "HC-005": _HC_005,
    "HC-006": _HC_006,
    "HC-009": _HC_009,
}

_OA_SCENARIOS = {
    "OA-004": _OA_004,
    "OA-005": _OA_005,
    "OA-006": _OA_006,
}


def evaluate_hc(case: dict[str, Any], context: RunContext) -> Evaluation:
    return _evaluate_scenario(case, context, _HC_SCENARIOS[case["case_id"]])


def evaluate_oa(case: dict[str, Any], context: RunContext) -> Evaluation:
    return _evaluate_scenario(case, context, _OA_SCENARIOS[case["case_id"]])
