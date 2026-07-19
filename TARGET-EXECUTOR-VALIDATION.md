# Target Executor Validation

This rubric governs any attempt to replace `BLOCKED_BY_ACCESS` with exact archived-target evidence. A successful build is necessary but is not sufficient.

## HC-011 — PortfolioCommandCenter hostile webview authority

1. **Immutable subject:** execute the archived commit `772be25eed8554defa55505cadd23e7fc61df982`, bound to archive SHA-256 `3494719b24d3ebfda24c97dbf363c1958f850f553fec98dd462094cb017111e9`, without source deviations.
2. **Original path reachability:** exercise hostile webview content through the target's actual Tauri IPC path to the registered proposal-approval and external-apply commands.
3. **Controls:** a deliberately vulnerable control must reach a run-owned canary, while the exact target must reject the same attempted authority transition.
4. **Containment:** use a disposable browser/webview profile, deny network and external writes, expose no normal profile or secrets, enforce resource ceilings, and prove cleanup.
5. **Evidence ceiling:** static capability review, frontend mocks, fixture-only browser execution, or successful compilation cannot produce PASS or FAIL for this runtime claim.

## HC-012 — PortfolioCommandCenter ambient path and command identity

1. **Immutable subject:** execute the archived commit and archive digest listed for HC-011 with no source deviations.
2. **Original path reachability:** exercise the target's original command construction, evidence-path binding, proposal lock, apply confirmation, and spawned-producer receipt paths.
3. **Controls:** fake paths, binaries, and stale/mismatched evidence must be rejected or confined; valid exact inputs must remain accepted; a vulnerable control must demonstrate that the canary can detect ambient substitution.
4. **Containment:** confine all process, filesystem, environment, network, and temporary effects to program-owned roots and prove cleanup after bounded execution.
5. **Evidence ceiling:** source inspection or unrelated target unit tests cannot retire the blocker unless the executed tests cover every claimed ambient-state path and preserve exact-source binding.

## LP-007 — AIGCCore no network action

1. **Immutable subject:** execute archived commit `09c3aa435a608d03c002782e6268c10f5bb7fe94`, bound to archive SHA-256 `18b71db9ee9b2c01c25e87f60c1396fb11fa39a21a9b352d2a0c5203c7992ae2`, without source deviations.
2. **Original path reachability:** exercise the target's UI, Tauri command, core adapter, and dependency paths that can initiate network activity.
3. **Controls:** an attempt sensor must observe a deliberately vulnerable network control, while observing no attempt from the exact subject across the complete exercised surface.
4. **Containment:** deny successful network egress and undeclared writes, use isolated homes/caches/profiles, enforce resource ceilings, and prove cleanup.
5. **Evidence ceiling:** policy objects, token scans, mocked adapters, sandbox denial without an attempt sensor, or partial core tests cannot establish the claim.
