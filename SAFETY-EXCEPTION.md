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
