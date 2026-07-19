# Gate 1B containment qualification contract

Gate 1B is a versioned execution contract, not a checklist. Active adversarial
fixtures remain disabled until every required qualification below passes in one
run against the same harness digest and recorded runtime identity.

The qualification receipt records `MHAI-CONTAINMENT-1`, the harness source
digest, OS/runtime versions, exact cached container image ID, start/finish
times, individual observations, cleanup state, and an overall verdict. The
qualified image must also contain every runtime later used for exact official
SDK or read-only target-archive execution. Any missing, contradictory, or
invalid record fails the gate.

## Exact qualification cases

### CQ-001 — canary sensitivity

- The positive control writes one unique value through the effect broker.
- The negative control writes nothing.
- The observer must distinguish both, detect later modification, and reject a
  canary whose run ID, nonce, or digest does not match.

### CQ-002 — path boundary

- Resolve the sacrificial root before execution.
- Reject lexical traversal, absolute outside paths, symlink escape, symlink
  replacement after validation, and multiply linked writable files.
- Open writable canaries without following links and verify device, inode,
  link count, owner, real parent, and run nonce before and after mutation.

### CQ-003 — exact-socket network boundary

- Start one listener inside the current isolated domain and one unrelated
  listener outside it, each on a dynamic port with a unique nonce.
- The positive control must reach the exact internal listener.
- The subject must fail to reach the unrelated listener, another loopback port,
  a non-loopback address, DNS, and cloud-metadata-shaped addresses.
- Success means a completed nonce exchange, not merely a socket return code.
- A fixture receives no Docker socket, proxy variables, host gateway alias, or
  inherited listener descriptor.

### CQ-004 — independent watchdog and controller death

- Start the watchdog before the subject as a separate process with its own
  minimal environment.
- The watchdog identifies the containment domain by immutable runtime ID plus a
  random run label, never by a reusable host PID alone.
- Inside the domain, create an ordinary child, a `setsid` child, and a
  double-fork-shaped detached descendant. Each schedules the same canary write
  for 750 milliseconds after controller loss.
- Kill the controller without running its cleanup handler.
- The watchdog must revoke the lease, terminate the complete containment
  domain, verify the immutable runtime ID and label again, and exit.
- Observe for 3 seconds after teardown. No delayed canary may appear.
- PID reuse is tested by starting an unrelated short-lived process after
  controller death; the watchdog must not signal it.

### CQ-005 — emergency stop

- While a fixture is active, atomically revoke the run lease through the
  emergency-stop path.
- The complete containment domain must end within 2 seconds.
- The same 3-second delayed-action window and immutable-identity cleanup checks
  from CQ-004 apply.

### CQ-006 — result-channel separation

- Fixture-writable paths and stdout contain forged `PASS`, result JSON, escape
  sequences, oversized nesting, and a valid-looking case ID/digest.
- Fixture output must persist only as bounded untrusted observations.
- Only the trusted oracle may create a result record, in a path the fixture
  cannot write. A forged result or evidence pointer must be rejected.

### CQ-007 — fail-closed redaction

- Positive controls contain synthetic token, cookie, authorization, private-key,
  home-path, control-character, and encoded-secret patterns.
- Negative controls preserve ordinary diagnostic fields.
- Oversized, over-depth, invalid-byte, and redaction-error inputs produce no raw
  persisted evidence and fail the affected run.
- Persisted records are at most 256 KiB and are rescanned before acceptance.

### CQ-008 — resource ceilings

- Active probes and runtime inspection verify: 30-second absolute wall limit,
  16 PIDs, 64 descriptors, 256 MiB memory, 8 MiB file limit, read-only root,
  non-root user, all capabilities dropped, no-new-privileges, bounded temporary
  storage, and no writable mount except the declared sacrificial path.
- Request, response, decompression, redirect, schema-depth, and evidence limits
  have separate boundary tests at limit minus one, limit, and limit plus one.

### CQ-009 — cleanup completeness

- After each qualification, enumerate by immutable run label and verify zero
  processes, containers, listeners, mounts, namespaces, browser profiles, open
  canary descriptors, writable temporary paths, and scheduled delayed actions.
- Cleanup is idempotent. A deliberately retained positive-control artifact must
  make cleanup fail until it is removed.

### CQ-010 — duplicate and stale qualification rejection

- A case ID may execute once per run ID.
- Replayed result records and reused run IDs are rejected.
- Qualification is invalid after any harness, safety contract, watchdog,
  container image, or relevant runtime identity digest changes.

### CQ-011 — synthetic execution environment

- Launch an observer through the exact fixture executor with synthetic
  credential-, proxy-, cloud-, Git-, SSH-, connector-, token-, and
  cookie-shaped environment variables present in the controller.
- The observer records key names only and must see exactly the case allowlist.
- `HOME`, `TMPDIR`, configuration, cache, and state roots must be fresh
  run-owned paths or isolated in-memory filesystems. `PATH` must be an explicit
  fixed runtime path and may not include a user or package-manager directory.
- Working directory, inherited descriptors, user/group identity, umask, and
  process limits must match the plan. No controller or host control socket may
  be inherited.
- The positive control intentionally exposes one synthetic sentinel key so the
  inventory proves it can detect leakage. The qualified executor must remove it.

### CQ-012 — browser profile isolation or hard refusal

- Browser cases are executable only through a separately qualified launcher.
- The positive control points a disposable browser at a synthetic account,
  extension, saved-state, and sync marker inside a sacrificial profile and must
  observe those markers.
- The qualified launcher must create a new profile under the run-owned
  sacrificial root, reject symlinks and hard links, disable accounts, sync,
  extensions, password storage, device APIs, clipboard authority, and normal
  profile import, and run inside the qualified network/filesystem boundary.
- The observer verifies that normal browser profile paths are neither mounted,
  opened, inherited, nor named in the child command line or environment.
- If no launcher can prove all of these properties, CQ-012 passes only in
  `BROWSER_DISABLED` mode: the harness must refuse every browser-dependent case
  as `BLOCKED_BY_ACCESS`. It may not fall back to an in-app, logged-in, normal,
  or merely command-line-separated profile.
- The bounded local search and rejected cached candidates are recorded in
  `BROWSER-CANDIDATE-ASSESSMENT.md`. A failed repeatability probe is not browser
  coverage and is not retried by ordinary qualification.
- Cleanup must remove the disposable profile and prove no browser process,
  profile lock, or delayed action remains.

## Gate verdict

Gate 1B passes only if CQ-001 through CQ-012 pass, their evidence validates, the
3-second delayed-action observations complete, and final cleanup is clean.
`BROWSER_DISABLED` is a safe Gate 1B mode but blocks every browser-dependent
case; it is never browser coverage.
`run-safe` recomputes the qualification binding before each run. Any failure,
missing control, stale digest, or cleanup residue yields `ERROR` and prevents
active adversarial execution.
