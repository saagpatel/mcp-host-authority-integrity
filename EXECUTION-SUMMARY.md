# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784468030-1099ef795c1c` produced 57 schema-valid, hash-bound case results: 43 `PASS`, 1 `FAIL`, and 13 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784467983-db5d77793fba` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation; pre-epoch side effects `SE-002` and `SE-003` also remain preserved. None is repaired or reinterpreted.

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

- Qualification: `cq-1784468010-d4f4d6f7396a` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `BROWSER_DISABLED`.
- Qualification digest: `93e9eadcc06df5b46eb32eef4fc1e54de01fa93e8c69f4574065eedd2427f5d1`.
- Fixture digest: `df7979c40a5b4f5d2a726fde8b8cbe4e1f4d3e52db22088639007df78d0d1b9d`.
- Closure epoch: `closure-1784467983-db5d77793fba` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `9c77b145cad48b96b92ac8175a223e14d41cf1af56ab75f244c3e7cb24388e23`.
- Final cleanup: `PASS`.

## Evidence boundary

- Browser-required cases blocked because every locally cached disposable launcher candidate failed repeatable CQ-012 qualification; no normal user browser profile was read, mounted, imported, or launched.
- The Go SDK case remains blocked because no exact official Go SDK exists in bounded local caches.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- Other isolated-copy cases remained blocked where source ownership was unclear or active.
- No target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
- `SE-002` preserves the macOS crash-diagnostic writes caused by failed pre-epoch browser probes.
- `SE-003` preserves the two diagnostic `/tmp` redirection files; neither file was opened for content inspection, altered, moved, or deleted.
