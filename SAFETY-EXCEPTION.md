# Safety exception

## SE-001 — target Git index stat-cache refresh

- Classification: `SAFETY_BOUNDARY_VIOLATION`
- Phase: Gate 7 closeout readback
- Observed at: `2026-07-19T10:07:34.218413524Z`
- Target: `/<HOME>/Projects/_claude-worktrees/portfolio-index-forge`
- Command shape: `git -C <target> status --porcelain=v1`
- Closure-gate effect: `FAIL`

The final target inventory omitted `--no-optional-locks` and
`GIT_OPTIONAL_LOCKS=0`. The shared worktree index mtime advanced to the
observation time, consistent with Git refreshing its index stat cache.

No command in this program requested a ref, commit, tracked file, untracked
worktree file, branch, or target content change. The only target mutation
directly attributable to this readback is the index mtime refresh. The readback
saw commit
`812192ac06ce5a43ebccd7b9a2f7bdaff5506269`, branch
`feat/wave1-calibration`, and four dirty paths owned by other work. No prior
index digest was recorded, so an exact byte-for-byte preimage comparison is
unavailable.

The exception occurred after the first complete run and before the final
requalification and rerun. The later current receipts do not erase the
violation, and the exception does not change their hash-bound case results. It
does invalidate the stronger Gate 7 claim that no forbidden target mutation
occurred. The program therefore reports execution complete but closure gate
failed.

No restoration or target-side repair was attempted. Further target Git reads
must use `git --no-optional-locks` or `GIT_OPTIONAL_LOCKS=0`.

## SE-002 — pre-epoch browser crash diagnostics outside the program root

- Classification: `LIFECYCLE_SIDE_EFFECT_OUTSIDE_PROGRAM_ROOT`
- Phase: pre-epoch disposable-browser launcher qualification exploration
- Observed at: `2026-07-19T05:07:40-07:00` through
  `2026-07-19T05:08:14-07:00`
- External writer: macOS `ReportCrash` / `osanalyticshelper`
- Closure-gate effect: historical pre-epoch exception; excluded from no later
  epoch window

Two deliberately over-tight `sandbox-exec` trials caused Chromium and GPU
subprocess failures while the launcher boundary was being derived. macOS
lifecycle services then created six diagnostic reports under
`/<HOME>/Library/Logs/DiagnosticReports`:

- `chrome-headless-shell-2026-07-19-050740.ips`
- `chrome-headless-shell-2026-07-19-050811.ips`
- `chrome-headless-shell-2026-07-19-050812.000.ips`
- `chrome-headless-shell-2026-07-19-050812.ips`
- `chrome-headless-shell-2026-07-19-050814.000.ips`
- `chrome-headless-shell-2026-07-19-050814.ips`

Those writes were performed by the operating system rather than by the
launcher process, but they are attributable to the program's failed probes and
occurred outside the program-owned sacrificial root. They therefore cannot be
described as perfectly no-write.

No target repository, normal browser profile, account, saved browser state,
connector, or external network endpoint was opened by the probes. Browser
writes were otherwise confined to fresh program-owned profiles. The reports
were not opened for content inspection, altered, moved, or deleted.

The launcher candidate was ultimately rejected because it did not prove
repeatable bounded execution. Hard refusal reduces recurrence risk but does not
repair or erase `SE-002`.

## SE-003 — diagnostic process inventory wrote outside the program root

- Classification: `PROGRAM_SIDE_EFFECT_OUTSIDE_PROGRAM_ROOT`
- Phase: pre-epoch disposable-browser watchdog diagnosis
- Observed at: `2026-07-19T06:14:34-07:00`
- Command shape: `/bin/ps -g <nonexistent-pgid> ...` with stdout and stderr
  redirected to `/tmp/mhai-ps-out` and `/tmp/mhai-ps-err`
- Closure-gate effect: historical pre-epoch exception; excluded from no later
  epoch window

The diagnostic command directly created `/tmp/mhai-ps-out` as a zero-byte file
and `/tmp/mhai-ps-err` as a 36-byte file. Both files were observed by metadata
only. They were not opened for content inspection, altered, moved, or deleted.

The command targeted a deliberately nonexistent process group and did not read
or modify any target repository, normal browser profile, account, secret,
connector, or external endpoint. The write locations nevertheless fell
outside the program-owned sacrificial root and are preserved as a safety
exception. Retiring the experimental launcher removes the active launcher path
and reduces recurrence risk, but does not repair or erase `SE-003`.

## SE-004 — pre-epoch catalog verification wrote outside the program root

- Classification: `PROGRAM_SIDE_EFFECT_OUTSIDE_PROGRAM_ROOT`
- Phase: continuation preflight catalog verification
- Observed at: `2026-07-19T07:05:51-07:00`
- Command shape: `python3 -m harness.runner list` with stdout redirected to
  `/tmp/mhai-case-list.txt`
- Closure-gate effect: historical pre-epoch exception; excluded from the later
  epoch window

The preflight command created or truncated `/tmp/mhai-case-list.txt` outside
the program-owned root. The file is 2,450 bytes, has SHA-256
`5f6c1682873ca5c629b02ae25add57af54afcb018d654be742a955bda575013c`,
and contained only the generated synthetic 57-case catalog listing.

The file was subsequently read to verify its line count, final total, and
digest. It was not altered after the initial redirection, moved, or deleted.
No target repository, normal browser profile, account, secret, connector, or
external endpoint was accessed by the command. Future catalog-list validation
must stream directly between processes or use a path under the program-owned
root. This exception remains preserved and is not repaired or erased.

## Later closure epochs

A later, explicitly bounded closure epoch may establish that its own observation
window caused no forbidden target mutation. That is separate evidence only.
It cannot repair, erase, downgrade, or reinterpret `SE-001`; the historical
Gate 7 outcome above remains `FAIL`. It likewise cannot erase or reinterpret
the pre-epoch side effects recorded as `SE-002`, `SE-003`, and `SE-004`.
