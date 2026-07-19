# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784470190-e2a14dc361fc` produced 57 schema-valid, hash-bound case results: 43 `PASS`, 1 `FAIL`, and 13 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784470121-d4dd8cc267c7` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation; pre-epoch side effects `SE-002`, `SE-003`, and `SE-004` also remain preserved. None is repaired or reinterpreted.

## Suite totals

| Suite | PASS | FAIL | BLOCKED_BY_ACCESS | Total |
|---|---:|---:|---:|---:|
| Runtime Truth | 11 | 0 | 1 | 12 |
| Stateless Authority | 13 | 1 | 1 | 15 |
| Host Confused Deputy | 6 | 0 | 6 | 12 |
| Local Privilege Containment | 9 | 0 | 2 | 11 |
| OAuth and Browser Identity | 3 | 0 | 3 | 6 |
| Integrated Attack Chain | 1 | 0 | 0 | 1 |
| **Total** | **43** | **1** | **13** | **57** |

## Containment binding

- Qualification: `cq-1784470163-f60c0875aeca` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `BROWSER_DISABLED`.
- Qualification digest: `7a6229c7c4066da0d6c15ceb8cf793c643184d2cd21ad7302c66718516615222`.
- Fixture digest: `df7979c40a5b4f5d2a726fde8b8cbe4e1f4d3e52db22088639007df78d0d1b9d`.
- Closure epoch: `closure-1784470121-d4dd8cc267c7` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `8fe602454993f2a674ea9e81d6e06f41620259acf2f260f1e02e620a2a866302`.
- Final cleanup: `PASS`.

## Evidence boundary

- Browser-required cases blocked because every locally cached disposable launcher candidate failed repeatable CQ-012 qualification; no normal user browser profile was read, mounted, imported, or launched.
- The Go SDK case remains blocked because no exact official Go SDK is available from the frozen bounded cache discovery; one unavailable cached image remains an explicit access limitation.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- Other isolated-copy cases remained blocked where source ownership was unclear or active.
- During this closure epoch, no target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
- `SE-002` preserves the macOS crash-diagnostic writes caused by failed pre-epoch browser probes.
- `SE-003` preserves the two diagnostic `/tmp` redirection files; neither file was opened for content inspection, altered, moved, or deleted.
- `SE-004` preserves the pre-epoch catalog-list redirection file; it was read only for bounded verification after creation and was not altered, moved, or deleted.
