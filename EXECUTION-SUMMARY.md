# Execution summary

## Outcome

`EXECUTION_COMPLETE_CLOSURE_GATE_FAIL`

The bound run `run-1784457876-5689c98bd88c` produced 57 schema-valid, hash-bound case results. No case produced `FAIL`, `UNKNOWN`, `ERROR`, `NOT_RUN`, or `NOT_IMPLEMENTED`. The run recorded 43 fixture, static-contract, or contained-oracle passes and 14 explicit access blocks.

No validated target vulnerability was established. A fixture `PASS` proves only the exact recorded synthetic subject and controls; it is not evidence that an installed target is secure or vulnerable.

Gate 7 closure failed because a final `git status` readback refreshed the shared `portfolio-index` worktree's Git index stat cache. The command did not request a ref, content, or worktree-file change; only the index mtime refresh is directly attributable to it. The strict no-write target boundary cannot be claimed. See `SAFETY-EXCEPTION.md`.

## Suite totals

| Suite | PASS | BLOCKED_BY_ACCESS | Total |
|---|---:|---:|---:|
| Runtime Truth | 11 | 1 | 12 |
| Stateless Authority | 13 | 2 | 15 |
| Host Confused Deputy | 6 | 6 | 12 |
| Local Privilege Containment | 9 | 2 | 11 |
| OAuth and Browser Identity | 3 | 3 | 6 |
| Integrated Attack Chain | 1 | 0 | 1 |
| **Total** | **43** | **14** | **57** |

## Containment binding

- Qualification: `cq-1784457861-f4d3957b171e` / `PASS`.
- Qualification checks: 12/12 `PASS`.
- Browser mode: `BROWSER_DISABLED`.
- Qualification digest: `46e81147afecec95a8207a80ddb77af35a325766006661c435164bcdc3224893`.
- Fixture digest: `0a01c75ccc63999079bdce56bc4b32be6fbcd945fbc64216dc86dd1f75a8b734`.
- Final cleanup: `PASS`.

## Evidence boundary

- Browser-required cases blocked because the disposable browser launcher was not qualified; no normal user browser profile was read.
- Official-SDK cases blocked because exact isolated SDK versions were not available under the no-network, no-package-manager boundary.
- Live-target and isolated-copy cases blocked where active ownership, source drift, or missing immutable copies prevented faithful execution.
- No target repair, content/ref/worktree edit, publication, external write, disclosure, push, or deploy was performed.
- The Gate 7 target no-write assertion failed due to the Git index stat-cache refresh recorded in `SAFETY-EXCEPTION.md`.
