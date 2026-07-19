"""Browser-executed fixture-host controls for browser-required cases."""

from __future__ import annotations

import json
from dataclasses import dataclass
from typing import Any

from harness.browser_runtime import BrowserRuntimeError, BrowserSession, browser_html
from harness.execution import Evaluation, RunContext
from suite_impl.common import ScenarioDecision, controlled_evaluation


@dataclass(frozen=True)
class BrowserScenario:
    attacks: tuple[str, ...]
    safe_script: str
    safe_reason: str
    safe_csp: str | None = None
    limitations: tuple[str, ...] = ()


def _vulnerable_script(attacks: tuple[str, ...]) -> str:
    encoded = json.dumps(attacks)
    return f"""
const attacks = {encoded};
const accepted = [];
window.addEventListener("mhai-attack", (event) => accepted.push(event.detail));
for (const variant of attacks) {{
  window.dispatchEvent(new CustomEvent("mhai-attack", {{detail: variant}}));
}}
mhaiFinish({{
  accepted_variants: accepted,
  legitimate_control: true,
  browser_events_dispatched: attacks.length
}});
"""


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
    context.case_root.mkdir(parents=True, exist_ok=True, mode=0o700)
    positive_root = context.case_root / "browser-positive"
    negative_root = context.case_root / "browser-negative"
    try:
        with BrowserSession(positive_root) as session:
            positive = session.run_html(
                browser_html(_vulnerable_script(scenario.attacks))
            )
        with BrowserSession(negative_root) as session:
            negative = session.run_html(
                browser_html(scenario.safe_script, csp=scenario.safe_csp)
            )
    except BrowserRuntimeError as exc:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=[
                {
                    "case_id": case["case_id"],
                    "browser_mode": context.browser_mode,
                    "browser_runtime_error": str(exc),
                    "unsafe_fallback_refused": True,
                }
            ],
            positive_control="FAIL",
            negative_control="FAIL",
            containment_result="FAIL",
            cleanup_result=(
                "PASS"
                if not positive_root.exists() and not negative_root.exists()
                else "FAIL"
            ),
            declared_result="ERROR",
            limitations=["The qualified browser runtime failed closed."],
        )

    cleanup_verified = not positive_root.exists() and not negative_root.exists()
    vulnerable_accepts = positive.payload.get("accepted_variants")
    safe_accepts = negative.payload.get("accepted_variants")
    legitimate = negative.payload.get("legitimate_control")
    shape_valid = (
        isinstance(vulnerable_accepts, list)
        and all(isinstance(item, str) for item in vulnerable_accepts)
        and isinstance(safe_accepts, list)
        and all(isinstance(item, str) for item in safe_accepts)
        and legitimate is True
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
    if not shape_valid:
        return Evaluation(
            target_verdict="UNKNOWN",
            observations=observations,
            positive_control="FAIL",
            negative_control="FAIL",
            declared_result="ERROR",
            limitations=[
                *scenario.limitations,
                "A browser control emitted an invalid result shape.",
            ],
        )
    if not isinstance(vulnerable_accepts, list) or not isinstance(safe_accepts, list):
        raise AssertionError("browser result shape was not narrowed after validation")
    vulnerable_values = [str(item) for item in vulnerable_accepts]
    safe_values = [str(item) for item in safe_accepts]
    attacks = list(scenario.attacks)
    vulnerable_for_control = (
        vulnerable_values if sorted(vulnerable_values) == sorted(attacks) else []
    )
    evaluation = controlled_evaluation(
        case,
        context,
        attack_variants=attacks,
        safe_decisions=[
            ScenarioDecision(variant in safe_values, scenario.safe_reason)
            for variant in attacks
        ],
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


HC_001 = BrowserScenario(
    attacks=(
        "forged-source",
        "forged-origin",
        "forged-server-connection",
        "forged-request-id",
        "stale-lifecycle",
        "reply-before-initialize",
    ),
    safe_reason=(
        "the host compared exact frame, origin, server, request, lifecycle, and "
        "initialization bindings"
    ),
    safe_script=r"""
const expected = {
  source: window, origin: "https://app.fixture.invalid", server: "server-a",
  request: "request-a", lifecycle: "document-a", initialized: true
};
const attacks = [
  {name:"forged-source", source:null, origin:expected.origin, server:expected.server, request:expected.request, lifecycle:expected.lifecycle, initialized:true},
  {name:"forged-origin", source:window, origin:"https://attacker.fixture.invalid", server:expected.server, request:expected.request, lifecycle:expected.lifecycle, initialized:true},
  {name:"forged-server-connection", source:window, origin:expected.origin, server:"server-b", request:expected.request, lifecycle:expected.lifecycle, initialized:true},
  {name:"forged-request-id", source:window, origin:expected.origin, server:expected.server, request:"request-b", lifecycle:expected.lifecycle, initialized:true},
  {name:"stale-lifecycle", source:window, origin:expected.origin, server:expected.server, request:expected.request, lifecycle:"document-old", initialized:true},
  {name:"reply-before-initialize", source:window, origin:expected.origin, server:expected.server, request:expected.request, lifecycle:expected.lifecycle, initialized:false}
];
const allowed = (value) => (
  value.source === expected.source && value.origin === expected.origin &&
  value.server === expected.server && value.request === expected.request &&
  value.lifecycle === expected.lifecycle && value.initialized === true
);
const accepted = attacks.filter(allowed).map((value) => value.name);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: allowed({...expected}),
  exact_window_identity_compared: true
});
""",
)


HC_005 = BrowserScenario(
    attacks=(
        "undeclared-egress",
        "redirect-egress",
        "nested-frame",
        "clipboard",
        "camera",
        "microphone",
        "geolocation",
    ),
    safe_reason="the fixture host policy rejected every undeclared browser authority",
    safe_csp=(
        "default-src 'none'; script-src 'unsafe-inline'; frame-src 'none'; "
        "connect-src 'none'; img-src 'none'; media-src 'none'; object-src 'none'; "
        "base-uri 'none'; form-action 'none'"
    ),
    safe_script=r"""
const requests = [
  {name:"undeclared-egress", kind:"egress"},
  {name:"redirect-egress", kind:"redirect"},
  {name:"nested-frame", kind:"frame"},
  {name:"clipboard", kind:"permission"},
  {name:"camera", kind:"permission"},
  {name:"microphone", kind:"permission"},
  {name:"geolocation", kind:"permission"}
];
const authorize = (request) => request.kind === "declared-local-render";
const accepted = requests.filter(authorize).map((request) => request.name);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: authorize({kind:"declared-local-render"}),
  csp: document.querySelector('meta[http-equiv="Content-Security-Policy"]').content,
  prohibited_dom_effects_created: 0
});
""",
)


HC_006 = BrowserScenario(
    attacks=(
        "invisible-click",
        "programmatic-click",
        "fake-pointer-event",
        "stale-gesture",
        "unrelated-gesture",
    ),
    safe_reason=(
        "only a recent visible relevant trusted-host gesture matched the exact action"
    ),
    safe_script=r"""
const attacks = ["invisible-click","programmatic-click","fake-pointer-event","stale-gesture","unrelated-gesture"];
const button = document.createElement("button");
document.body.appendChild(button);
const accepted = [];
const trust = [];
button.addEventListener("click", (event) => {
  trust.push(event.isTrusted);
  if (event.isTrusted && !button.hidden) accepted.push(button.dataset.variant);
});
for (const variant of attacks) {
  button.dataset.variant = variant;
  button.hidden = variant === "invisible-click";
  if (variant === "fake-pointer-event") button.dispatchEvent(new MouseEvent("click"));
  else button.click();
}
const hostApprove = (gesture) => (
  gesture.source === "trusted-host-chrome" && gesture.age <= 500 &&
  gesture.visible && gesture.relevant && gesture.server === "server-a" &&
  gesture.tool === "consequential-tool" && gesture.argumentsDigest === "args-a"
);
mhaiFinish({
  accepted_variants: accepted,
  legitimate_control: hostApprove({
    source:"trusted-host-chrome", age:20, visible:true, relevant:true,
    server:"server-a", tool:"consequential-tool", argumentsDigest:"args-a"
  }),
  programmatic_events_all_untrusted: trust.every((value) => value === false)
});
""",
)


HC_009 = BrowserScenario(
    attacks=(
        "cross-origin-registration",
        "sibling-frame-call",
        "stale-after-navigation",
        "stale-after-replacement",
        "stale-after-frame-removal",
        "delegation-missing",
    ),
    safe_reason=(
        "registrations were bound to exact origin, frame, document, connection, "
        "and delegation"
    ),
    safe_script=r"""
const container = document.createElement("div");
document.body.appendChild(container);
const frame = (origin, doc) => {
  const value = document.createElement("iframe");
  value.dataset.origin = origin; value.dataset.doc = doc;
  container.appendChild(value); return value;
};
const register = (value, delegated=true) => ({
  frame:value, origin:value.dataset.origin, doc:value.dataset.doc, delegated
});
const callable = (registration, value, origin, delegated=true) => (
  registration.frame === value && value.isConnected &&
  registration.origin === origin && value.dataset.origin === origin &&
  registration.doc === value.dataset.doc && registration.delegated && delegated
);
const accepted = [];
let value = frame("https://app.fixture.invalid","cross");
let registration = register(value);
if (callable(registration,value,"https://attacker.fixture.invalid")) accepted.push("cross-origin-registration");
value.remove();
value = frame("https://app.fixture.invalid","sibling-a");
let sibling = frame("https://app.fixture.invalid","sibling-b");
registration = register(value);
if (callable(registration,sibling,sibling.dataset.origin)) accepted.push("sibling-frame-call");
value.remove(); sibling.remove();
value = frame("https://app.fixture.invalid","before");
registration = register(value); value.dataset.doc = "after";
if (callable(registration,value,value.dataset.origin)) accepted.push("stale-after-navigation");
value.remove();
value = frame("https://app.fixture.invalid","replace");
registration = register(value);
const replacement = frame("https://app.fixture.invalid","replace");
value.replaceWith(replacement);
if (callable(registration,replacement,replacement.dataset.origin)) accepted.push("stale-after-replacement");
replacement.remove();
value = frame("https://app.fixture.invalid","removed");
registration = register(value); value.remove();
if (callable(registration,value,value.dataset.origin)) accepted.push("stale-after-frame-removal");
value = frame("https://app.fixture.invalid","delegation");
registration = register(value,false);
if (callable(registration,value,value.dataset.origin,false)) accepted.push("delegation-missing");
value.remove();
value = frame("https://app.fixture.invalid","legitimate");
registration = register(value,true);
const legitimate = callable(registration,value,value.dataset.origin,true);
value.remove();
mhaiFinish({accepted_variants:accepted, legitimate_control:legitimate});
""",
)


OA_004 = BrowserScenario(
    attacks=(
        "port-race",
        "wrong-state",
        "pkce-swap",
        "redirect-uri-swap",
        "second-tab",
        "code-replay",
    ),
    safe_reason=(
        "completion compared exact redirect, state, PKCE verifier, browser flow, "
        "and one-shot code state"
    ),
    limitations=(
        "URL routing is browser-executed with the outer network boundary deny-all; no live callback listener is opened.",
    ),
    safe_script=r"""
const newFlow = () => ({
  redirect:"http://127.0.0.1:49152/callback", state:"state-a",
  verifier:"verifier-a", browserFlow:"tab-a", consumed:new Set()
});
const complete = (flow, candidate) => {
  const url = new URL(candidate.url);
  const code = url.searchParams.get("code");
  if (`${url.origin}${url.pathname}` !== flow.redirect ||
      url.searchParams.get("state") !== flow.state ||
      candidate.verifier !== flow.verifier ||
      candidate.browserFlow !== flow.browserFlow ||
      !code || flow.consumed.has(code)) return false;
  flow.consumed.add(code); return true;
};
const base = {
  url:"http://127.0.0.1:49152/callback?code=code-a&state=state-a",
  verifier:"verifier-a", browserFlow:"tab-a"
};
const variants = [
  ["port-race",{url:"http://127.0.0.1:49153/callback?code=code-a&state=state-a"}],
  ["wrong-state",{url:"http://127.0.0.1:49152/callback?code=code-a&state=state-b"}],
  ["pkce-swap",{verifier:"verifier-b"}],
  ["redirect-uri-swap",{url:"http://127.0.0.1:49152/other?code=code-a&state=state-a"}],
  ["second-tab",{browserFlow:"tab-b"}],
  ["code-replay",{}]
];
const accepted = [];
for (const [name, patch] of variants) {
  const flow = newFlow(); const candidate = {...base,...patch};
  if (name === "code-replay") complete(flow,candidate);
  if (complete(flow,candidate)) accepted.push(name);
}
const legitimateFlow = newFlow();
const legitimate = complete(legitimateFlow,base) && !complete(legitimateFlow,base);
mhaiFinish({accepted_variants:accepted, legitimate_control:legitimate});
""",
)


OA_005 = BrowserScenario(
    attacks=(
        "trusted-brand-loopback-redirect",
        "logo-confusion",
        "unicode-brand",
        "metadata-redirect-mismatch",
        "redirect-after-approval",
    ),
    safe_reason="the approval DOM displayed and bound the normalized actual redirect",
    safe_script=r"""
const expected = "https://client.fixture.invalid/callback";
const code = document.createElement("code");
code.id = "actual-redirect"; code.textContent = expected;
document.body.appendChild(code);
const attacks = [
  ["trusted-brand-loopback-redirect","http://127.0.0.1:62222/callback"],
  ["logo-confusion","http://localhost:63333/callback"],
  ["unicode-brand","http://127.0.0.1:64444/callback"],
  ["metadata-redirect-mismatch","https://attacker.fixture.invalid/callback"],
  ["redirect-after-approval","https://redirected.fixture.invalid/callback"]
];
const authorize = (redirect) => (
  new URL(redirect).href === new URL(expected).href && code.textContent === expected
);
mhaiFinish({
  accepted_variants:attacks.filter(([,url]) => authorize(url)).map(([name]) => name),
  legitimate_control:authorize(expected),
  displayed_redirect:code.textContent,
  metadata_brand_used_for_authority:false
});
""",
)


OA_006 = BrowserScenario(
    attacks=(
        "bob-completes-alice",
        "client-swap",
        "punycode-destination",
        "redirected-destination",
        "parameter-tamper",
        "completion-replay",
    ),
    safe_reason=(
        "completion compared initiating user, client, normalized destination, "
        "parameter digest, and one-shot state"
    ),
    safe_script=r"""
const newFlow = () => ({
  user:"alice", client:"client-a",
  destination:new URL("https://alice.fixture.invalid/complete").href,
  request:"request-a", parameterDigest:"params-a", consumed:false
});
const complete = (flow, candidate) => {
  if (flow.consumed || candidate.user !== flow.user ||
      candidate.client !== flow.client ||
      new URL(candidate.destination).href !== flow.destination ||
      candidate.request !== flow.request ||
      candidate.parameterDigest !== flow.parameterDigest) return false;
  flow.consumed = true; return true;
};
const base = {
  user:"alice", client:"client-a",
  destination:"https://alice.fixture.invalid/complete",
  request:"request-a", parameterDigest:"params-a"
};
const variants = [
  ["bob-completes-alice",{user:"bob"}],
  ["client-swap",{client:"client-b"}],
  ["punycode-destination",{destination:"https://xn--lice-43d.fixture.invalid/complete"}],
  ["redirected-destination",{destination:"https://redirected.fixture.invalid/complete"}],
  ["parameter-tamper",{parameterDigest:"params-b"}],
  ["completion-replay",{}]
];
const accepted = [];
for (const [name,patch] of variants) {
  const flow = newFlow(); const candidate = {...base,...patch};
  if (name === "completion-replay") complete(flow,candidate);
  if (complete(flow,candidate)) accepted.push(name);
}
const legitimateFlow = newFlow();
const legitimate = complete(legitimateFlow,base) && !complete(legitimateFlow,base);
mhaiFinish({accepted_variants:accepted, legitimate_control:legitimate});
""",
)


HC_SCENARIOS = {
    "HC-001": HC_001,
    "HC-005": HC_005,
    "HC-006": HC_006,
    "HC-009": HC_009,
}
OA_SCENARIOS = {
    "OA-004": OA_004,
    "OA-005": OA_005,
    "OA-006": OA_006,
}


def evaluate_hc(case: dict[str, Any], context: RunContext) -> Evaluation:
    return _evaluate_scenario(case, context, HC_SCENARIOS[case["case_id"]])


def evaluate_oa(case: dict[str, Any], context: RunContext) -> Evaluation:
    return _evaluate_scenario(case, context, OA_SCENARIOS[case["case_id"]])
