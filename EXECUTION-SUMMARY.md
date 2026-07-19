# Execution summary

## Outcome

`EXECUTION_COMPLETE_NEW_EPOCH_PASS_WITH_HISTORICAL_EXCEPTION`

The bound run `run-1784461483-9e9faacaa0da` produced 57 schema-valid, hash-bound case results: 43 `PASS`, 1 `FAIL`, and 13 `BLOCKED_BY_ACCESS`. No case produced `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`.

One low-severity exact-SDK interoperability finding was validated in `SA-015`. It is not evidence of an authorization bypass in a particular host. A fixture `PASS` proves only the recorded synthetic subject and controls.

The new closure epoch `closure-1784461445-0f3f973ae17a` passed its own no-forbidden-mutation gate. Target identities were frozen once with both optional-lock controls; final checks performed no target inventory and did not invoke target Git. Historical `SE-001` remains a violation and is not repaired or reinterpreted.

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

- Qualification: `cq-1784461460-d74e3dbb9b1a` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `BROWSER_DISABLED`.
- Qualification digest: `9f896a138a05f1ac9bd8a160d53bd0b1ae6fe967ffc3495e9e359dd9f45b6720`.
- Fixture digest: `015bd5099ab40146443997ca53cd45575325003459931d62ef7ec2cca49fd122`.
- Closure epoch: `closure-1784461445-0f3f973ae17a` / `PASS_WITH_HISTORICAL_EXCEPTION`.
- Closure digest: `82224d8eea4adbd0ae5eb86a273d85102031885a84da00760e6ddb3bb81cd1ca`.
- Final cleanup: `PASS`.

## Evidence boundary

- Browser-required cases blocked because the disposable browser launcher was not qualified; no normal user browser profile was read.
- The Go SDK case remains blocked because no exact official Go SDK exists in bounded local caches.
- Exact Python and TypeScript SDK parsers executed from the qualified cached image with network disabled.
- `RT-012` remained blocked because no fidelity-proven mcp-trust archive was available; the live target was not executed.
- Other isolated-copy cases remained blocked where source ownership was unclear or active.
- No target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- `SE-001` remains the historical Gate 7 violation. The new epoch's passing gate is separate evidence and does not repair it.
