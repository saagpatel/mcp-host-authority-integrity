# Duplicate and exclusion ledger

The program preserves every requested case ID but deduplicates shared fixture
implementation and refuses to present already-shipped work as a new finding.

| Cases / area | Disposition |
|---|---|
| RT-001–RT-003 | Existing MCPAudit prompt-injection examples are static/config-only. Retain runtime retrieval/call cases. |
| RT-004–RT-007 | MCPAudit records annotations and initial list metadata but does not prove effects, cursor exhaustion, or list-change refresh. Retain. |
| RT-010 | Exclude broad fanout/performance work; retain post-timeout delayed canary and process-containment proof. |
| RT-011 | Exclude generic SafeForge/pre-install work; retain exact container isolation flags with synthetic probes. |
| RT-012 | Retain the exact live-target claim, but block execution: Git identity may be read while live mcp-trust code cannot execute without an approved immutable contained copy. |
| SA-009 / HC-006 / OA-006 | Exclude the already reproduced null-elicitation confirmation fail-open. Retain correlation, gesture laundering, and initiating-user binding. |
| HC-011 / HC-012 | Existing path, queue, receipt, and producer checks are controls, not hostile-webview proof. Retain isolated-copy reachability and ambient launch poisoning. |
| LP-001 | Existing one-port cookie tests do not prove cross-port authority. Retain synthetic two-port case. |
| LP-002 | Exclude a generic agent platform; retain one program-owned effective-authority experiment. |
| LP-006 | Existing BridgeDB write-principal tests remain duplicate. Narrow to live read contracts plus fixture principal matrix. |
| LP-008 | Exclude general signed-receipt work; retain adjacent attacker-key substitution versus independent identity anchoring. |
| LP-009 | Existing public fixture receipt is a negative control, not dynamic aggregation proof. Retain. |
| LP-010 / LP-011 | Exclude generic schema fuzzing; retain exact remote-reference and bounded exhaustion oracles. |
| Entire program | Exclude generic scanners, dependency/secret/CVE sweeps, automation contracts, Git recovery, installed-runtime drift, dashboards, governance systems, Spec-Shift Tribunal rework, and target repairs. |

Shared fixture clusters are documented in `DESIGN.md`; separate case results and
evidence ceilings are never merged.
