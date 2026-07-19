# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784482060-36ca22ae9f0c` produced 57 schema-valid, hash-bound case results: 51 `PASS`, 1 `FAIL`, and 5 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784482012-610879302d78` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation; pre-epoch side effects `SE-002`, `SE-003`, and `SE-004` also remain preserved. None is repaired or reinterpreted.

## Suite totals

| Suite | PASS | FAIL | BLOCKED_BY_ACCESS | Total |
|---|---:|---:|---:|---:|
| Runtime Truth | 11 | 0 | 1 | 12 |
| Stateless Authority | 14 | 1 | 0 | 15 |
| Host Confused Deputy | 10 | 0 | 2 | 12 |
| Local Privilege Containment | 9 | 0 | 2 | 11 |
| OAuth and Browser Identity | 6 | 0 | 0 | 6 |
| Integrated Attack Chain | 1 | 0 | 0 | 1 |
| **Total** | **51** | **1** | **5** | **57** |

## Containment binding

- Qualification: `cq-1784482031-c4f3444192b7` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `QUALIFIED`.
- Qualification digest: `3d100a3e7557ac013f47a0a376c83e1ef89e52976b2ca6e673669040035b54d6`.
- Fixture digest: `00ed9bf229cc7ab683334ae04769cbb355b30508669da4ba466064730557bea4`.
- Closure epoch: `closure-1784482012-610879302d78` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `3b31ee9c8855e0ef59c1ec9682091062e124140dad486fecea653d10643d8886`.
- Final cleanup: `PASS`.

## Evidence boundary

- CQ-012 qualified the exact official program-owned disposable browser. Seven fixture-browser cases executed with fresh profiles, network denied, normal profile roots denied, and clean process/profile cleanup. `HC-011` remained independently blocked on the target webview-command executor.
- `SA-014` executed the exact official Go MCP SDK v1.6.1 from program-owned storage with the network denied and all hostile Origin/Host inputs rejected.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- Fidelity-proven PortfolioCommandCenter and AIGCCore archives did not become behavioral proof: their locked build/runtime dependency lanes remained unavailable, so the target cases stayed blocked.
- During this closure epoch, no target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
- `SE-002` preserves the macOS crash-diagnostic writes caused by failed pre-epoch browser probes.
- `SE-003` preserves the two diagnostic `/tmp` redirection files; neither file was opened for content inspection, altered, moved, or deleted.
- `SE-004` preserves the pre-epoch catalog-list redirection file; it was read only for bounded verification after creation and was not altered, moved, or deleted.
