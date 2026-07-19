# Target Executor Validation

This rubric governs any attempt to replace `BLOCKED_BY_ACCESS` with exact archived-target evidence. A successful build is necessary but is not sufficient.

## HC-011 — PortfolioCommandCenter hostile webview authority

1. **Immutable subject:** execute the PortfolioCommandCenter commit and archive SHA-256 frozen by the current immutable closure-epoch receipt, without source deviations. The executable receipt must bind the same target name, commit, tree, archive digest, Cargo.lock digest, test inventory, and test-binary digest.
2. **Original path reachability:** exercise hostile webview content through the target's actual Tauri IPC path to the registered proposal-approval and external-apply commands.
3. **Controls:** a deliberately vulnerable control must reach a run-owned canary, while the exact target must reject the same attempted authority transition.
4. **Containment:** use a disposable browser/webview profile, deny network and external writes, expose no normal profile or secrets, enforce resource ceilings, and prove cleanup.
5. **Evidence ceiling:** static capability review, frontend mocks, fixture-only browser execution, or successful compilation cannot produce PASS or FAIL for this runtime claim.

## HC-012 — PortfolioCommandCenter ambient path and command identity

1. **Immutable subject:** execute the same current closure-epoch PortfolioCommandCenter commit and archive digest used for HC-011 with no source deviations.
2. **Original path reachability:** exercise the target's original command construction, evidence-path binding, proposal lock, apply confirmation, and spawned-producer receipt paths.
3. **Controls:** fake paths, binaries, and stale/mismatched evidence must be rejected or confined; valid exact inputs must remain accepted; a vulnerable control must demonstrate that the canary can detect ambient substitution.
4. **Containment:** confine all process, filesystem, environment, network, and temporary effects to program-owned roots and prove cleanup after bounded execution.
5. **Evidence ceiling:** source inspection or unrelated target unit tests cannot retire the blocker unless the executed tests cover every claimed ambient-state path and preserve exact-source binding.

## LP-007 — AIGCCore no network action

1. **Immutable subject:** execute the AIGCCore commit and archive SHA-256 frozen by the current immutable closure-epoch receipt, without source deviations. The executable receipt must bind the same target name, commit, tree, archive digest, Cargo.lock digest, feature set, test inventory, and test-binary digest.
2. **Original path reachability:** exercise the target's UI, Tauri command, core adapter, and dependency paths that can initiate network activity.
3. **Controls:** an attempt sensor must observe a deliberately vulnerable network control, while observing no attempt from the exact subject across the complete exercised surface.
4. **Containment:** deny successful network egress and undeclared writes, use isolated homes/caches/profiles, enforce resource ceilings, and prove cleanup.
5. **Evidence ceiling:** policy objects, token scans, mocked adapters, sandbox denial without an attempt sensor, or partial core tests cannot establish the claim.

## LP-009 — portfolio-index public aggregation boundary

1. **Immutable subject:** execute the portfolio-index commit and archive SHA-256 frozen by the current immutable closure-epoch receipt, without source deviations. The source executor receipt must bind the same target name, commit, tree, and archive digest.
2. **Original path reachability:** import and execute the archived public-project generator against synthetic structured project records; do not substitute a reimplemented safe path.
3. **Controls:** the safe subject must retain a named public control while excluding unique private-repository and private-owner markers; a deliberately vulnerable aggregator must leak both private markers to the run-owned canary.
4. **Containment:** use only synthetic records and program-owned temporary roots, expose no live portfolio records or credentials, perform no network or target-checkout access, and prove cleanup.
5. **Evidence ceiling:** source inspection, rendered-output string scans, or a public-only fixture without a vulnerable leakage control cannot establish the claim.
