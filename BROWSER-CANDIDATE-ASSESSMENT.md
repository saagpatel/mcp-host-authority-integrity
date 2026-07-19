# Disposable browser candidate assessment

## Current candidate

`ELIGIBLE_FOR_CQ_012`

The operator authorized one official disposable Playwright browser in
program-owned storage. The exact candidate is:

- Playwright `1.62.0-alpha-2026-07-19`
- Chromium headless-shell revision `1234`
- Chromium `151.0.7922.34`
- program path
  `vendor/official/playwright-browsers/chromium_headless_shell-1234`

`OFFICIAL-DEPENDENCY-PROVENANCE.json` binds the package integrity, download
URL, browser revision/version, browser binary hash, Playwright metadata hash,
and a canonical bundle-tree hash.

The candidate is not qualified merely because it was downloaded. CQ-012 must
repeat three fresh-profile launches and prove on every launch:

- macOS outer-sandbox `deny network*`;
- explicit denial of normal browser profile roots;
- no normal profile path in the subject command or environment;
- one fresh program-owned profile;
- bounded process and memory observations;
- zero residual process-group members;
- zero crash-diagnostic changes; and
- exact browser identity before and after execution.

Only a schema-valid `QUALIFIED` receipt enables browser cases. A launch,
containment, identity, cleanup, or repeatability failure returns the program to
hard refusal.

## Initial bounded probe

The revision `1234` candidate completed an initial sandboxed `about:blank`
probe with exit status zero. The outer sandbox denied network access and all
known normal browser profile roots. HOME, TMPDIR, and the browser profile were
fresh program-owned paths. The probe left no process residue and created or
changed no macOS diagnostic report.

This probe is discovery evidence, not the formal CQ-012 receipt.

## Historical rejected candidates

The earlier cache-only assessment remains preserved:

| Cache revision | Browser version | Playwright metadata | Historical result |
|---|---|---|---|
| `1208` | Chromium `145` | Playwright `1.58.2` | rejected |
| `1217` | Chromium `147` | Playwright `1.59.1` | rejected |
| `1223` | Chromium `148.0.7778.96` | Playwright `1.60.0` | rejected |
| `1228` | Chromium `149.0.7827.55` | Playwright `1.61.1` | rejected unstable |

Revision `1228` produced intermittent successes and later timeouts. Revisions
`1208` and `1217` timed out. Revision `1223` completed one temporary probe and
failed a repeat run. Those results are not reinterpreted by the new candidate.

`HC-011` also requires an exact PortfolioCommandCenter archive and an
independently adequate target executor. Browser qualification alone cannot
turn fixture evidence or an unexecuted archive into target proof.

## Preserved side effects

The over-tight historical probes caused the operating-system diagnostic writes
recorded as `SE-002`. A historical process-inventory diagnostic created the two
`/tmp` files recorded as `SE-003`. Neither exception is repaired or erased by
the new candidate.
