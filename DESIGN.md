# Program design

## One program, not four disconnected projects

The four suites share the same authority tuple:

`principal + server + connection + operation + arguments + state + approval + expiry`

They also share the same evidence problem: declared metadata and backend state
can disagree with runtime behavior, visible host state, or the final side effect.
One harness therefore owns planning, containment, canaries, observations,
oracles, evidence, cleanup, and result validation across every suite.

## Architecture

1. **Immutable case catalog**
   - Contains all 57 requested case IDs.
   - Binds one exact subject claim, protocol status, sources, evidence ceiling,
     allowed and forbidden effects, controls, timeout, cleanup, and limitations.
   - The required `result` field is an immutable declaration sentinel fixed to
     `NOT_RUN`; execution results are separate records.

2. **Plan compiler**
   - Resolves the case definition, subject/version/configuration, numeric limits,
     fixture family, and run-specific synthetic principals.
   - Hashes the case definition before execution.
   - Refuses an unversioned subject or a coverage claim above the case ceiling.

3. **Execution supervisor**
   - Runs one case per fresh containment domain.
   - Uses argv-only process execution, a synthetic environment, explicit
     resource ceilings, an out-of-process watchdog, and monotonic leases.
   - Risky cases remain serial until containment qualification passes.
   - Binds every run to one immutable closure-epoch receipt.

4. **Deny-by-default effect broker**
   - Is the only path to filesystem, network, command, approval, browser, or
     external-write-shaped canaries.
   - Allows only program-owned paths and run-owned socket identities.
   - Records attempts separately from allowed effects.

5. **Parameterized fixture families**
   - MCP descriptor/runtime server and host.
   - State/task/authority and OAuth service.
   - App/frame/host and browser policy.
   - Local process, desktop copy, filesystem, signature, and schema worker.

6. **Evidence collector and deterministic oracle**
   - Untrusted fixture output is data, never a structured control channel.
   - Redaction occurs before persistence with byte and depth limits.
   - The oracle records raw observations, subject verdict, positive and negative
     control status, containment, cleanup, contradictions, and final result.

## Deterministic verdict precedence

1. Invalid or missing controls, containment, validation, or cleanup -> `ERROR`.
2. Required authority or access absent -> the matching `BLOCKED_*`.
3. Fail oracle true and pass oracle false -> `FAIL`.
4. Pass oracle true, fail oracle false, evidence complete -> `PASS`.
5. Neither oracle or contradictory observations -> `UNKNOWN`.

A positive control may trigger a target-forbidden but program-allowed canary.
It may never cross the program safety boundary.

## Evidence ladder

Coverage records both an allowed enum and a richer subject descriptor:

- `LIVE_TARGET`
- `ISOLATED_TARGET_COPY` with source digest and deviation manifest
- `OFFICIAL_SDK` with exact package/runtime version
- `FIXTURE_HOST`
- `FIXTURE_SERVER`
- `STATIC_EVIDENCE_ONLY`

Evidence from different levels is never merged into a stronger claim.

## Gate split

### Gate 1A — architecture freeze

All cases, sources, schemas, exact subject claims, protocol statuses, evidence
ceilings, deterministic verdict rules, threat model, and containment proof
obligations exist and validate.

### Gate 1B — containment qualification

Canaries, exact-socket egress denial, watchdog, controller-death cleanup,
detached-process emergency stop, path containment, redaction, resource ceilings,
result-channel separation, duplicate rejection, PID-reuse resistance, and cleanup
all pass against the exact oracles in `CONTAINMENT-QUALIFICATION.md`. Attack
execution is impossible before this gate.

### Gate 7 — bounded closure epoch

A closure epoch starts only from a clean program-owned checkpoint. Its opening
receipt freezes every target identity using both `GIT_OPTIONAL_LOCKS=0` and
`git --no-optional-locks`; ordinary execution consumes those frozen identities
and does not reinventory targets.

When a target is clean and ownership is clear, the opener may create a
program-owned immutable `git archive` at the frozen commit. The archive is
accepted only after its file set, modes, and every blob object ID match the
frozen Git tree. Archive contents are made read-only and their digest is bound
into the epoch.

The close step invokes no target inventory and no target Git command. It
validates every case result and manifest hash, requires the opening reads to
have preserved their before/after metadata, and verifies case-level evidence
that later execution used only frozen identities or a fidelity-proven
program-owned archive. Concurrent target drift is outside that claim and is
neither attributed to this program nor represented as stability. A passing
later epoch is separate evidence; it never erases or repairs historical safety
exception `SE-001` or the pre-epoch side effects `SE-002`, `SE-003`, and
`SE-004`.

## Integrated chain

The chain records each transition independently. A stopped chain does not mark
downstream defenses as passed. A deliberately vulnerable all-fixture control
chain proves that the sensors can observe the full path, while the safe chain
reports the first effective defense and any earlier failed defenses.
