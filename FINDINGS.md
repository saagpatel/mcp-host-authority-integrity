# Findings

The complete bound run `run-1784457876-5689c98bd88c` produced no validated
target finding. Its machine-readable finding set is the empty array in
`results/findings.json`.

The run recorded 43 `PASS` results and 14 `BLOCKED_BY_ACCESS` results. The
passes apply to exact synthetic fixtures, local static-contract checks, or
contained oracles at their declared evidence ceilings. They do not establish
that an unexecuted installed target is secure, and the deliberately vulnerable
positive controls are harness controls rather than product vulnerabilities.

Candidate observations must pass validation with:

- reproducible execution;
- valid positive and negative controls;
- exact subject component, version, and configuration;
- one named trust boundary and concrete unauthorized outcome or misleading claim;
- redacted evidence and deterministic reproduction;
- limitations and alternative explanations;
- independent confirmation for High or Critical severity.

Fixture-only behavior is not a third-party product vulnerability.
