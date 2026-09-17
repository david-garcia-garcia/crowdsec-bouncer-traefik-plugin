# Assessment

- relevant: yes
- kind: bug
- affected: no
- status: present-fixed-unproven
- proof: none
- recommended-action: **add-tests**
- slug: 2026-09-06-upstream-319-stream-cache-log-spam
- rationale: Upstream v1.6.0-alpha promoted `handleStreamCache:updated` from DEBUG to INFO, so the stream poll tick (default 60s) flooded Traefik logs at the default plugin log level; upstream closed with PR #324 reverting to DEBUG. On `master`, `pkg/lapi/client_stream.go` still polls via `handleStreamCache` but logs both `handleStreamCache:updated` and `handleStreamCache:alreadyUpdated` with `c.log.Debug`, while operator-visible stream health uses `logInfo` (INFO). Default `pkg/logger` level is INFO, so the reported spam does not appear unless operators set `loglevel=DEBUG`, where periodic debug lines are expected.
- evidence current: pkg/lapi/client_stream.go, pkg/logger/logger.go
- tests: pkg/lapi/client_range_test.go

Bound: this run is **add-tests** — do not change product behavior unless a test cannot be honest without a one-line correctness fix. The PR exists to prove we do not have the upstream problem.
