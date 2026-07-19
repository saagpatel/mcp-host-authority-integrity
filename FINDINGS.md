# Findings

The complete bound run `run-1784496308-d351acead7de` validated one evidence-bounded finding.

## MHAI-SA-015-001 — Official Python and TypeScript SDKs diverge on a conflicting request envelope

- Severity: `LOW`
- Coverage: `OFFICIAL_SDK`
- Version: `package:python-mcp+typescript-sdk@1.28.1+1.29.0`
- Trust boundary: Untrusted JSON-RPC request envelope to SDK request dispatch.

Python accepts and selects params.name='danger' for an envelope carrying a conflicting top-level name='safe', while TypeScript rejects the same envelope; cross-SDK execution equivalence is therefore unsafe to assume.

This does not establish an authorization bypass in a downstream host. The machine-readable finding, controls, evidence, limitations, and alternative explanations are in `results/findings.json`.
