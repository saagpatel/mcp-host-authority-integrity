# Execution authority grant

## Operator grant

The operator authorized Codex to:

- Download an official disposable Playwright browser and the official Go MCP
  SDK into program-owned folders only.
- Create read-only archives of `mcp-trust`, `PortfolioCommandCenter`,
  `AIGCCore`, and `portfolio-index`, but only when each repository is clean and
  has no active owner.
- Run a new complete verification epoch.

The operator explicitly prohibited:

- Modifying any original target repository.
- Using a normal browser profile.
- Exposing secrets.
- Pushing, publishing, deploying, or repairing target projects.

## Operational binding

- Network access is limited to official Playwright and official Go module
  distribution endpoints needed for the two authorized downloads.
- All download caches, extracted packages, browser profiles, build state,
  temporary files, and evidence must remain under this program repository.
- Every target Git read must set `GIT_OPTIONAL_LOCKS=0` and invoke
  `git --no-optional-locks`.
- An archive is eligible only when the target is clean, no live process or
  current handoff claims the target, no Git lock is present, and exact
  tree/blob/mode fidelity is proven before the archive is accepted.
- A missing dependency, failed qualification, dirty target, active owner, or
  incomplete fidelity proof remains blocked. It is never converted into a
  pass.
- Historical safety exceptions `SE-001` through `SE-004` remain preserved and
  unrepaired.
