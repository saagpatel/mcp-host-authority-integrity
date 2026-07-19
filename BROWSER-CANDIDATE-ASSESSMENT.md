# Disposable browser candidate assessment

## Verdict

`REJECTED_UNSTABLE`

No locally cached browser candidate proved repeatable execution under the full
CQ-012 profile, filesystem, network, lifecycle, and resource boundary. The
active qualification mode is therefore `BROWSER_DISABLED`.

## Bounded local discovery

Only the existing Playwright browser cache and already cached containment
images were inspected. No package was installed, no network endpoint was used,
and no normal browser profile was read, mounted, imported, or launched.

| Cache revision | Browser version | Playwright metadata |
|---|---|---|
| `1208` | Chromium `145` | Playwright `1.58.2` |
| `1217` | Chromium `147` | Playwright `1.59.1` |
| `1223` | Chromium `148.0.7778.96` | Playwright `1.60.0` |
| `1228` | Chromium `149.0.7827.55` | Playwright `1.61.1` |

The cached containment image did not contain a browser executable. The host
cache candidates required an outer macOS `sandbox-exec` launcher and fresh
program-owned profile.

## Qualification attempts

- Revision `1228` in single-process mode produced intermittent successes and
  later timeouts. That unsupported mode did not establish repeatability.
- Revisions `1208` and `1217` timed out under the bounded multi-process
  launcher.
- Revision `1223` completed one seven-case fixture pass under a temporary
  browser-only 384 MiB probe ceiling, then failed a repeat run. That ceiling
  was never promoted into the active safety boundary.
- After reducing watchdog observer load, the final bounded serial probe failed
  all seven fixture-host browser cases at the wall-time ceiling:
  `HC-001`, `HC-005`, `HC-006`, `HC-009`, `OA-004`, `OA-005`, and `OA-006`.

`HC-011` was never eligible because it independently requires a clean,
explicitly owned, fidelity-proven PortfolioCommandCenter archive.

No resource, sandbox, profile, or cleanup control was weakened to turn this
candidate into a pass. The experimental launcher implementation was retired
from the active harness so later qualifications do not repeatedly execute an
unstable runtime.

## Preserved side effects

The over-tight early sandbox probes caused the operating system diagnostic
writes recorded as `SE-002`. A later process-inventory diagnostic directly
created the two `/tmp` files recorded as `SE-003`. Those artifacts were not
opened for content inspection, altered, moved, or deleted.
