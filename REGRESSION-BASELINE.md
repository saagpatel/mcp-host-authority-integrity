# Regression baseline

## Status

`CANONICAL_LOCAL_BASELINE`

This file pins the accepted MCP Host Authority Integrity evidence chain and
defines when a new epoch is warranted. It does not authorize target access,
target repair, publication, or an automatic rerun.

## Canonical evidence

- Program evidence commit:
  `29b273d086826258f46e94c9ae2c9b15eb00d073`
- Closure epoch: `closure-1784499573-6dced0579571`
- Containment qualification: `cq-1784499726-d1b961ffed3c`
- Complete run: `run-1784499743-0d91c88f094f`
- Result: 56 `PASS`, 1 `FAIL`, 0 `BLOCKED_BY_ACCESS`
- Preserved finding: `SA-015`
- Closure result: `PASS_WITH_HISTORICAL_EXCEPTION`
- No-forbidden-mutation gate: `PASS`

The canonical rendered artifacts are `EXECUTION-SUMMARY.md`,
`EXECUTION-COVERAGE.md`, `FINDINGS.md`, and the receipts under
`results/latest/`.

The same-archive run `run-1784499839-2c7f0f618d0f` reproduced the 56/1/0
counts after the epoch had already closed. It is supplementary evidence only;
the immutable epoch correctly refused a second terminal close.

## Frozen target identities

| Target | Commit | Tree |
|---|---|---|
| mcp-trust | `f8582c7ddd663d2ebdcd2b75dbe8b2f7f26ec462` | `bdc61b679f06136d84cefaabc6928c0a9f82c030` |
| PortfolioCommandCenter | `564bd41df34a959aaf3593aa01ea0b337334b4f3` | `b2a93b87794652e9c7b2c2bbf8f155a812973697` |
| AIGCCore | `94b28bff8fec69e25d1c761845764a95496b8dad` | `341b1f1f306fe1de3b9ed74965fdc18f16c1e89b` |
| portfolio-index | `e28c9d12849dd3b27454e64f90e8a54cd3608807` | `583be14d52b60883b892c8aae615dffb91047080` |

PortfolioCommandCenter PR
[`#33`](https://github.com/saagpatel/PortfolioCommandCenter/pull/33)
landed the verified hardening on `main` as
`ac10eb2f26bf858d00f8617b91ea395216122935`. The merged commit has the exact
verified tree `b2a93b87794652e9c7b2c2bbf8f155a812973697`.

## Rerun triggers

A new target-owner preparation and one newly authorized closure epoch are
required when any of the following becomes true:

1. A frozen target commit or tree changes for a case that uses archived-target
   evidence.
2. A registered PortfolioCommandCenter executable sink, Tauri IPC command, or
   source-owned integrity hook changes.
3. An official Python or TypeScript MCP SDK stable release changes the
   `SA-015` parser behavior, or the protocol/conformance project resolves the
   unknown-member contract.
4. Program case contracts, schemas, containment controls, executor preparation,
   or dependency provenance change in a way that can affect a verdict.
5. Exact evidence identifies a contradiction in the canonical receipts or
   rendered claims.

Routine scheduling, elapsed time alone, or an unchanged upstream issue are not
rerun triggers.

## Drift detector

Run:

```sh
python3 scripts/check_regression_drift.py
```

The detector compares local target commits and trees under an isolated
disposable Git `HOME`, with both optional-lock controls enabled and no fetch.
It checks the Python SDK's current PyPI release, the TypeScript SDK's current
GitHub release, protocol issue `#1898`, and conformance PR `#399` through
read-only upstream API calls.

Exit codes are:

- `0`: no rerun trigger;
- `10`: material drift requires review;
- `20`: required evidence is unavailable or ambiguous.

The JSON report is printed to standard output and is not persisted. A fatal
baseline or schema error emits a smaller JSON error envelope and exits `20`.
The detector never edits, cleans, switches, fetches, builds, or repairs a
target, never opens an epoch, and never authorizes a rerun.

## Rerun contract

- Target-owner work must finish before the program observes targets.
- The next target-facing operation after eligibility verification must be the
  newly authorized epoch-open.
- Every target Git read must use `GIT_OPTIONAL_LOCKS=0` and
  `git --no-optional-locks` with an isolated disposable Git `HOME`.
- After epoch-open, execution must use only the newly frozen program-owned
  archives.
- A new run must not overwrite, reinterpret, or repair this baseline or its
  historical safety exceptions.
