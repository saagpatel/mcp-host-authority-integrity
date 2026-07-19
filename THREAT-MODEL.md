# Threat model

## Overview

This repository builds a synthetic adversarial harness for authority integrity
across MCP descriptors, runtime protocol behavior, state and tasks, host/client
mediation, embedded applications, local processes, and machine-side effects.
The primary security objective is to keep every decision and effect bound to the
correct principal, server, connection, operation, arguments, state, approval,
expiry, and evidence provenance.

The program never treats fixture behavior as proof about an installed product.
Its own supervisor, brokers, oracles, evidence store, and cleanup system are part
of the trusted computing base and are explicit attack targets.

## Threat Model, Trust Boundaries, and Assumptions

### Actors

- Malicious MCP server or compromised server dependency.
- Malicious MCP App/iframe, hostile same-origin frame, or delegated cross-origin
  frame.
- Malicious or confused local process and compromised sibling MCP server.
- Untrusted subagent with more effective OS/tool authority than its prompt scope.
- Authenticated user A attacking user B.
- OAuth issuer, metadata, redirect, callback, or resource mix-up attacker.
- Attacker controlling a manifest, signature, and adjacent verification key.
- Attacker supplying malformed protocol data, schemas, headers, or JSON.
- Attacker replaying handles, tasks, approvals, input responses, or continuations.
- Attacker exploiting stale caches, list state, template review, or capability
  negotiation.
- Attacker relying on misleading safety annotations or simulated receipts.
- Local port racer, DNS/proxy/cache manipulator, ambient OS user/environment,
  fixture dependency attacker, and controller-death attacker.
- Harness/controller attacker attempting evidence forgery, canary corruption,
  redaction bypass, cleanup escape, or result-channel injection.

### Assets

- Tool, filesystem, local-process, host-command, connector, and external-write
  authority.
- User identity, OAuth grants/tokens, approvals, state handles, task results, and
  request correlation.
- BridgeDB read data, private project metadata, model context, app-to-host
  messages, and audit evidence.
- Canary integrity, result/redaction integrity, source-copy provenance,
  containment leases, watchdog state, and the evidence store.

### Trust boundaries

1. Server descriptor -> retrieved server content.
2. Retrieved content -> host model context and approval surface.
3. Approval surface -> tool selection, exact arguments, and execution.
4. Transport bytes -> JSON/HTTP parsing and canonical authorization identity.
5. Request -> explicit state, input response, task worker, cancellation, and
   result retrieval.
6. Cache lookup -> principal/server/method/argument/version/expiry binding.
7. Embedded content -> frame/origin/server/lifecycle-bound host messages.
8. UI gesture -> trusted host consent naming the real effect.
9. App/webview -> local host command bridge.
10. Local process -> sibling service, filesystem, environment, or machine effect.
11. DNS/proxy/redirect resolution -> final connected destination.
12. Subject output -> bounded observation, redaction, oracle, and persisted
    evidence.
13. Controller heartbeat -> watchdog, containment teardown, and cleanup.

### Assumptions

- All test principals, secrets, content, services, and effects are synthetic.
- Existing targets remain read-only and may have active owners or dirty work.
- A declared safety property, annotation, signature, exit code, simulated event,
  or backend terminal state is a claim, not proof.
- Missing, stale, inaccessible, masked, or unverifiable evidence is `UNKNOWN`.
- OS-level containment must be proven before intentionally hostile processes or
  browser content run.

## Attack Surface, Mitigations, and Attacker Stories

### Protocol and runtime surface

Attackers hide behavior behind list/get/call gaps, pagination, list changes,
client fingerprinting, collisions, malformed JSON, duplicate headers, stale
capabilities, or misleading annotations. Mitigations are complete enumeration,
runtime observations, origin-qualified identity, protocol-version separation,
bounded parsing, and deterministic differentials.

### State, task, cache, and OAuth surface

Attackers steal or tamper with handles, swap continuations, replay input
responses, cross tenant task APIs, race cancellation, exploit stale caches, forge
client identity, rotate rate-limit labels, mix issuers/resources, capture
callbacks, or complete another user's URL elicitation. Mitigations bind the full
authority tuple independently of possession, use single-use replay ledgers,
re-check authorization where the local contract requires it, partition caches,
and validate issuer/resource/redirect/state/PKCE relationships.

### Embedded UI and host-command surface

Attackers forge message source/origin/IDs, cross server connections, replace a
reviewed template, escape CSP/permissions, launder gestures, overwrite model
context, exploit unsupported fallback, retain stale WebMCP tools, escape ACP
roots, or poison desktop launch state. Mitigations bind frame, origin, server,
lifecycle, tool visibility, content digest, consent, path canonicalization, and
the final command choke point.

### Local containment and evidence surface

Attackers reuse loopback cookies, exceed delegated scope, replay approvals,
inherit environment or descriptors, pivot to siblings, confuse offline claims,
substitute verification keys, leak private labels, trigger remote schema reads,
or exhaust validators. The harness itself may be attacked through untrusted
stdout, oversized evidence, detached descendants, controller death, or fixture
writes to result paths. Mitigations are isolated namespaces, exact brokers,
synthetic state, independent watchdogs, resource caps, fail-closed redaction,
separate result storage, hashing, and cleanup verification.

### Out-of-scope attacker stories

Real accounts, credentials, third-party MCP servers, real connector writes,
production authorization grants, irreversible actions, disclosure, publication,
and target repair are outside this program. Their absence limits evidence and
severity; it is never silently converted into a pass.

## Severity Calibration (Critical, High, Medium, Low)

- **Critical** — verified real authority escape to sensitive data or irreversible
  effect. This level is not reachable under the authorized synthetic-only
  program and cannot be assigned from fixture evidence.
- **High** — verified unauthorized operation or cross-user disclosure in a live
  target or faithful pinned isolated copy, with the security-critical path
  unchanged. Requires independent confirmation.
- **Medium** — reproducible fail-open, misleading safety claim, approval/cache
  weakness, or containment gap without proven real-world impact. Fixture-only
  scope must appear in the title or scope.
- **Low** — bounded defense-in-depth weakness or ambiguity with limited impact.
  Unsupported coverage and proof gaps are normally `INFO`, not vulnerabilities.

Repository: mcp-host-authority-integrity
Version: snapshot:fe1e85a1e4fa82e9895cf3ccaa200d884fd24a8b60836eb992a35171687b5ffb
