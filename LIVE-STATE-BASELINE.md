# Live-state baseline

Captured read-only on 2026-07-19 before program execution.

## Gate 0 decision

`PASS_WITH_TARGET_LEASE_EXCLUSIONS`

The program repository was absent and could be created without overwriting work.
MCPAudit changed branch and became dirty during discovery, and personal-ops had
active feature work. Those checkouts are excluded from copying, building, or
runtime execution. This does not authorize weakening their cases: affected
live-target evidence is blocked or limited to prior read-only observations.

PortfolioTruth was generated on 2026-07-18 and was useful for attention routing,
but several Git facts had already drifted. The live Git read therefore controls.

## Read-only target inventory

| Target | Read-only baseline | Worktree decision |
|---|---|---|
| MCPAudit | `6980b28514fb`, dirty active feature branch | Active-owner exclusion; no copy/build/touch |
| mcp-trust | `7b1a66bd5e1a`, clean `main` | Read-only live interface may be observed |
| bridge-db | `a1aeb4c51438`, clean canonical checkout; unrelated dirty worktree exists | Live reads only; no synthetic principal enrollment |
| AIGCCore | `d8c570cf148b`, clean `main` | Pinned archive may be created in program-owned work |
| personal-ops | `3196ad90cb2c`, dirty active feature branch | Active-owner exclusion; LP-001 fixture only |
| PortfolioCommandCenter | `fb84c6ba169f`, clean canonical checkout; unrelated dirty worktrees exist | Pinned archive may be created in program-owned work |
| portfolio-index | bare canonical root; multiple worktrees including heavy dirt | No copy until one clean pinned worktree is explicitly selected |
| operant-public | `ace95d9b8604`, clean feature branch | Read-only, no current execution need |
| GithubRepoAuditor | `ad81ff746d59`, clean canonical checkout; unrelated dirty worktree exists | Read-only grounding only |
| operator-os-explainer | `fb8ddc881267`, clean `main` | Read-only grounding only |

## Other control-plane evidence

- BridgeDB had no pending/active handoffs and no write conflicts.
- BridgeDB health was degraded by a stale recovery anchor and legacy migration
  backup provenance. This program does not repair or reinterpret that condition.
- Recent Codex and Claude Code history was available as untrusted stored
  evidence. Full ChatGPT and Claude.ai conversation history was unavailable.
- No target fetch, pull, branch switch, clean, restore, submodule update, build,
  package-manager action, or write was performed.

## Evidence ceilings created by live state

- MCPAudit claims are static read-only evidence only; the active checkout is not
  a runtime subject.
- RT-012 may observe the exact mcp-trust read-only interface but cannot prove
  the future behavior of cataloged third-party servers.
- HC-011 and HC-012 may use only a pinned clean PortfolioCommandCenter archive
  and remain `ISOLATED_TARGET_COPY`.
- LP-006 remains live-contract inspection plus fixture authorization; it cannot
  claim live BridgeDB tenant isolation.
- LP-007 may use only a pinned clean AIGCCore archive.
- LP-001 remains a faithful synthetic fixture because the live personal-ops
  checkout and session state are excluded.
