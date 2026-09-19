# Assessment: upstream#370

- relevant: yes
- kind: bug
- affected: no
- status: present-fixed-unproven
- proof: none
- recommended-action: add-tests
- slug: 2026-09-06-upstream-370-stream-poll-lease-interval-one
- rationale: Our fork keeps the stream poll lease in `pkg/lapi/client_stream.go` (`handleStreamCache` stores `cacheTimeoutKey` for `leaseDuration` seconds). Upstream used `updateInterval - 1`, which is 0 when `updateIntervalSeconds` is 1—a supported value per `pkg/configuration/configuration.go` (`requiredInt1` enforces `>= 1`). Zero TTL is a no-op in the in-tree local cache (`golang-ttl-map`) and fails on Redis via `pkg/simpleredis` (`SET … EX 0`), so the lease guard would silently do nothing. We already floor the duration: `leaseDuration := c.updateInterval - 1; if leaseDuration < 1 { leaseDuration = 1 }`, matching upstream's suggested fix. No test on `master` asserts that `updateIntervalSeconds: 1` actually stores a lease.

## Evidence
- current: pkg/lapi/client_stream.go
- tests: pkg/lapi/client_range_test.go (lease-hit hydrate only; no interval=1 case)
