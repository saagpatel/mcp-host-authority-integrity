# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784491842-b2cf2d6a13bb` produced 57 schema-valid, hash-bound case results: 51 `PASS`, 2 `FAIL`, and 4 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784491807-80be8e41d02a` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation; pre-epoch side effects `SE-002`, `SE-003`, and `SE-004` also remain preserved. None is repaired or reinterpreted.

## Suite totals

| Suite | PASS | FAIL | BLOCKED_BY_ACCESS | Total |
|---|---:|---:|---:|---:|
| Runtime Truth | 11 | 0 | 1 | 12 |
| Stateless Authority | 14 | 1 | 0 | 15 |
| Host Confused Deputy | 10 | 1 | 1 | 12 |
| Local Privilege Containment | 9 | 0 | 2 | 11 |
| OAuth and Browser Identity | 6 | 0 | 0 | 6 |
| Integrated Attack Chain | 1 | 0 | 0 | 1 |
| **Total** | **51** | **2** | **4** | **57** |

## Containment binding

- Qualification: `cq-1784491823-750703bcada1` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `QUALIFIED`.
- Qualification digest: `239059119eab4e189356fb47996052d781db2683de810f78c6a9eb8d7ef455ea`.
- Fixture digest: `8261000263f7e12a711f22cc0ad5ff1890d0639440e2d9e341c7c26e31859035`.
- Closure epoch: `closure-1784491807-80be8e41d02a` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `e1684aa5521a92a5e343aea947381466264a977bdc9544188e126f602f77b8bc`.
- Final cleanup: `PASS`.

## Evidence boundary

- CQ-012 qualified the exact official program-owned disposable browser. Seven fixture-browser cases executed with fresh profiles, network denied, normal profile roots denied, and clean process/profile cleanup. `HC-011` remained independently blocked on the target webview-command executor.
- `SA-014` executed the exact official Go MCP SDK v1.6.1 from program-owned storage with the network denied and all hostile Origin/Host inputs rejected.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- `HC-012` executed the exact archived PortfolioCommandCenter command-spawn path and recorded a hostile `PATH` failure.
- `HC-011` remained blocked because no actual archived Tauri webview-to-command IPC executor was available.
- `LP-007` remained blocked because no complete AIGCCore UI, Tauri command, core adapter, dependency-path executor with a proven network-attempt sensor was available.
- During this closure epoch, no target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
- `SE-002` preserves the macOS crash-diagnostic writes caused by failed pre-epoch browser probes.
- `SE-003` preserves the two diagnostic `/tmp` redirection files; neither file was opened for content inspection, altered, moved, or deleted.
- `SE-004` preserves the pre-epoch catalog-list redirection file; it was read only for bounded verification after creation and was not altered, moved, or deleted.
