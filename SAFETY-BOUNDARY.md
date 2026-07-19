# Safety boundary

## Allowed

- Program-owned source, fixtures, results, canaries, temporary state, and local
  commits on the feature branch.
- Synthetic principals, credentials, cookies, tokens, approvals, tasks,
  handles, projects, schemas, OAuth services, and MCP hosts/servers.
- Dynamically assigned ports that are bound and recorded by the current run.
- Disposable processes and containers created for the current run from already
  cached images.
- Read-only source inspection and pinned isolated copies when the live target is
  clean and ownership is clear.

## Forbidden

- Changes in any existing target repository or operating surface.
- Real secrets, private content, accounts, OAuth grants, connectors, production
  credentials, arbitrary existing loopback listeners, or logged-in profiles.
- Third-party server probes, external writes, publication, disclosure, pushes,
  deployment, destructive actions, or target repairs.
- Shell interpolation of fixture data, uncontrolled protocol handlers, host
  Docker sockets inside fixtures, cloud metadata, LAN access, or external URLs
  during attack cases.

## Containment requirements

- Resolve a program-owned real path and reject symlink/hardlink escape.
- Run each case in fresh synthetic `HOME`, `TMPDIR`, `PATH`, and config state.
- Scrub proxy, cloud, Git, SSH, connector, token, and credential variables.
- Close inherited descriptors and expose no host control sockets.
- Allow network access only inside a run-owned isolated namespace or to exact
  run-owned socket identities. Arbitrary loopback is denied.
- Enforce wall time, CPU, memory, process, descriptor, file, request, response,
  decompression, redirect, schema-depth, and disk limits.
- Start the watchdog before the subject and revoke the lease on heartbeat loss.
- Use an ephemeral browser profile with no accounts, sync, extensions, saved
  state, devices, clipboard authority, or normal-profile reuse.
- Keep result storage outside fixture-writable paths.

## Default numeric ceilings

| Limit | Default |
|---|---:|
| Wall time per ordinary case | 10 seconds |
| Long task duration | 30 seconds |
| Child processes | 16 |
| Open file descriptors | 64 |
| Address space / RSS target | 256 MiB |
| Output file size | 8 MiB |
| Request body | 1 MiB |
| Response body | 2 MiB |
| Decompressed body | 4 MiB |
| Redirects | 5 |
| Schema depth | 64 |
| Evidence record | 256 KiB |

Case definitions may lower these limits. Increases require a new design review.

## Cleanup and emergency stop

Cleanup verifies run-owned processes, listeners, profiles, containers,
namespaces, mounts, identities, temporary files, and delayed canaries. It
preserves only validated redacted evidence.

The emergency stop revokes the run lease, terminates the containment domain,
waits through the delayed-action observation window, and verifies no canary
escaped. Cleanup failure aborts further execution and marks the affected case
`ERROR`; later cases remain `NOT_RUN`.

## Blocked classification

If safe containment, source-copy fidelity, a required runtime, or non-mutating
authority is unavailable, the case is not weakened. It is recorded as
`BLOCKED_BY_ACCESS`, `BLOCKED_BY_AUTHORITY`, or `UNKNOWN`.
