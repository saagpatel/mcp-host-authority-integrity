# MCP Host Authority Integrity Program

This is an executable, synthetic-only security research program for one question:

> Does trust and authority remain correctly bound as control moves from MCP
> descriptors through runtime behavior, state and tasks, host mediation,
> embedded applications, local processes, and machine-side effects?

It is not a generic MCP scanner, dashboard, governance layer, or dependency
sweep. It preserves 57 distinct security claims while sharing a small set of
deterministic fixtures and oracles.

## Current safety posture

Attack fixtures are gated. Definitions and architecture can be inspected at any
time, but adversarial execution is refused until the containment qualification
proves canaries, deny-by-default egress, emergency stop, cleanup, redaction, and
resource ceilings.

All effects are synthetic and restricted to program-owned sacrificial state.
Existing product repositories, services, accounts, connectors, and browser
profiles are read-only or out of scope.

## Quick start

```sh
ruff check .
mypy harness suite_impl scripts
python3 -m unittest discover -s tests -v
python3 scripts/generate_cases.py --check
python3 -m harness.runner list
git commit  # create a clean, program-owned local checkpoint
python3 -m harness.runner epoch-open
python3 -m harness.runner qualify
python3 -m harness.runner run-safe
python3 -m harness.runner epoch-close
python3 scripts/render_execution_evidence.py --write
python3 scripts/render_execution_evidence.py --check
```

`run-safe` refuses to start when qualification is missing, stale, or failed.
Case results distinguish target behavior from harness containment and control
health. A harness exit code is never treated as a security verdict by itself.
`epoch-open` also refuses a dirty program worktree. It freezes target identities
with `GIT_OPTIONAL_LOCKS=0` and `git --no-optional-locks`, creates an immutable
program-owned target archive only when cleanliness and ownership permit, and
binds the resulting receipt into qualification and execution. `epoch-close`
performs no target inventory or target Git command; it validates the frozen
opening reads, the case-level no-live-target-access evidence, and the hash-bound
run instead.

## Suites

- **Runtime Truth** — descriptor-versus-runtime behavior, pagination,
  notification refresh, server origin, timeout cleanup, and registry claims.
- **Stateless Authority** — handles, continuations, tasks, correlation, caches,
  claimed identity, rate limits, HTTP ambiguity, SDK differentials, and OAuth.
- **Host Confused Deputy** — app/frame binding, visibility, consent, template
  integrity, WebMCP lifecycle, ACP roots, and isolated desktop-host boundaries.
- **Local Privilege Containment** — loopback sessions, delegated authority,
  approvals, environment inheritance, sibling isolation, offline claims,
  signature identity, public leakage, and schema resource limits.
- **Integrated Chain** — one contained all-fixture composition with every trust
  transition recorded independently.

## Result interpretation

- `PASS`: the exact subject claim passed, both controls were valid, containment
  and cleanup passed, evidence was complete, and no contradiction was observed.
- `FAIL`: a deterministic forbidden target effect or misleading claim was
  reproduced while the harness remained valid.
- `BLOCKED_BY_AUTHORITY` / `BLOCKED_BY_ACCESS`: the safe boundary prevented the
  requested evidence.
- `UNKNOWN`: the available evidence cannot choose the pass or fail oracle.
- `ERROR`: the harness, controls, containment, validation, or cleanup failed.
- `NOT_IMPLEMENTED` / `NOT_RUN`: coverage is explicit and incomplete.

Fixture evidence never proves behavior in an installed or live target.

See [DESIGN.md](DESIGN.md), [THREAT-MODEL.md](THREAT-MODEL.md), and
[SAFETY-BOUNDARY.md](SAFETY-BOUNDARY.md) before execution.

The completed evidence overlay is in [EXECUTION-SUMMARY.md](EXECUTION-SUMMARY.md)
and [EXECUTION-COVERAGE.md](EXECUTION-COVERAGE.md). `COVERAGE-MATRIX.md` remains
the immutable pre-execution catalog view. [SAFETY-EXCEPTION.md](SAFETY-EXCEPTION.md)
records the Gate 7 closeout boundary violation.
It also records pre-epoch side effects outside the program root. Historical
`SE-001`, `SE-002`, `SE-003`, and `SE-004` are permanent program history. A
later closure epoch may pass its own gate, but cannot repair or reinterpret
them.

The bounded browser search is recorded in
[BROWSER-CANDIDATE-ASSESSMENT.md](BROWSER-CANDIDATE-ASSESSMENT.md). Historical
cache-only candidates remain rejected. The authorized official program-owned
candidate becomes executable only when the current CQ-012 receipt records
`QUALIFIED`; it never reads or reuses a normal profile.
