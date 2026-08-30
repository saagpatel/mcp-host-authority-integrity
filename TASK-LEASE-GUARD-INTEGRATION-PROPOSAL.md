# MCP Task Lease Guard integration proposal

## Decision and local status

Keep the Task Lease Guard as a fixture-only sidecar until its versioned protocol
profiles receive an explicit corpus-integration review. The existing 57-case
program and its closure receipts are bound to the legacy `2025-11-25` Tasks
source. Folding the current extension into those historical case meanings would
silently invalidate their evidence bindings. The approved local integration is
therefore additive: the historical 57-case execution contract stays unchanged,
while a separate generated baseline binds it to the 30-case `TLG-*` namespace.

## What is ready locally

- `task_lease_guard/cases.json` defines 30 deterministic synthetic cases.
- `scripts/check_task_lease_guard.py` emits `TaskLeaseGuardReportV1` JSON.
- The checker separates `released-core-2025-11-25` from
  `current-extension-2026-07-28` wire and lifecycle semantics.
- `task_lease_guard/protocol-drift.json` records the breaking comparison against
  the existing `SA-005` through `SA-009` corpus surface.
- PASS, FAIL, and UNKNOWN are all first-class outcomes. UNKNOWN is required for
  specification gaps rather than treated as success.
- `mhai task-lease-check` runs only the bundled fixtures and emits JSON to
  stdout; it does not enter qualification, containment, or closure-epoch paths.
- `task_lease_guard/integration-baseline.json` is the generated 87-case identity
  baseline and records the immutable historical catalog and receipt bindings.

## Proposed integration sequence

1. Keep `cases.json`, the historical suite catalogs, run manifests, closure
   contracts, and all result receipts fixed at their existing 57-case binding.
2. Append the current `2026-07-28` core, Tasks extension, authorization,
   elicitation, and deprecated-sampling sources to the active source registry;
   retain the prior 24-source digest in the integration baseline.
3. Keep the approved `TLG-*` suite namespace separate from existing `SA-*`
   meanings and use its own case and report schemas.
4. Route `mhai task-lease-check` directly to the deterministic sidecar checker
   without containment setup, target reads, closure epochs, or durable receipts.
5. Regenerate the 87-case identity baseline and require its preservation checks
   before accepting any future corpus change.
6. Run focused tests, the applicable parent suite, Ruff, MyPy, and both
   generated-output checks before accepting the local revision.

## Required claim boundary

A green Task Lease Guard report proves only that the local checker produced the
expected outcomes for its synthetic fixtures. It does not prove that any MCP
client, server, SDK, transport, installed runtime, or deployment implements the
same behavior. A FAIL is a fixture nonconformance, not an exploitable
vulnerability. UNKNOWN remains UNKNOWN until the owning specification or an
explicit local policy supplies the missing rule.

## Non-goals

- No live MCP traffic, credentials, client profiles, provider calls, or network
  behavior from the checker.
- No edits to MCPAudit, mcp-trust, AIGCCore, client configuration, or installed
  runtimes.
- No package publication, push, disclosure, deployment, or target remediation.
