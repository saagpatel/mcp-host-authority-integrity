# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784496308-d351acead7de` produced 57 schema-valid, hash-bound case results: 53 `PASS`, 2 `FAIL`, and 2 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784496134-a9e98dd015d8` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation; pre-epoch side effects `SE-002`, `SE-003`, and `SE-004` also remain preserved. None is repaired or reinterpreted.

## Suite totals

| Suite | PASS | FAIL | BLOCKED_BY_ACCESS | Total |
|---|---:|---:|---:|---:|
| Runtime Truth | 11 | 0 | 1 | 12 |
| Stateless Authority | 14 | 1 | 0 | 15 |
| Host Confused Deputy | 11 | 1 | 0 | 12 |
| Local Privilege Containment | 10 | 0 | 1 | 11 |
| OAuth and Browser Identity | 6 | 0 | 0 | 6 |
| Integrated Attack Chain | 1 | 0 | 0 | 1 |
| **Total** | **53** | **2** | **2** | **57** |

## Containment binding

- Qualification: `cq-1784496289-d722fcd60baa` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `QUALIFIED`.
- Qualification digest: `cf3c829449b5e69920daa64e905f2556651ef8b7031c509ded612811ae3cbe43`.
- Fixture digest: `d4cc6998114cba302e701decacf9889fbfd6e2fdb2e5212a4a1c2973b1316ed2`.
- Closure epoch: `closure-1784496134-a9e98dd015d8` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `940a1b6c5d73b86fc9017e49c477250668560e4588ae4340979a9eb472daad10`.
- Final cleanup: `PASS`.

## Evidence boundary

- CQ-012 qualified the exact official program-owned disposable browser. Seven fixture-browser cases executed with fresh profiles, network denied, normal profile roots denied, and clean process/profile cleanup.
- `SA-014` executed the exact official Go MCP SDK v1.6.1 from program-owned storage with the network denied and all hostile Origin/Host inputs rejected.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- `HC-012` executed the exact archived PortfolioCommandCenter command-spawn path and recorded a hostile `PATH` failure.
- `HC-011` executed the source-owned registered Tauri IPC dispatcher from the exact PortfolioCommandCenter archive; hostile remote origins were rejected before approval/apply effects and the vulnerable canary control was observed.
- `LP-007` executed the archived frontend request contract, Tauri dispatcher, production adapter runtime, and socket dependency; the loopback attempt sensor fired while non-loopback and malformed inputs were rejected before an attempt.
- `LP-009` remained blocked because no clean, fidelity-proven portfolio-index archive was available.
- During this closure epoch, no target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
- `SE-002` preserves the macOS crash-diagnostic writes caused by failed pre-epoch browser probes.
- `SE-003` preserves the two diagnostic `/tmp` redirection files; neither file was opened for content inspection, altered, moved, or deleted.
- `SE-004` preserves the pre-epoch catalog-list redirection file; it was read only for bounded verification after creation and was not altered, moved, or deleted.
