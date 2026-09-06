# Explore
IssueKey: 2026-09-06-upstream-370-stream-poll-lease-interval-one

## Concepts

**Stream poll lease**: cache key `updated` (`cacheTimeoutKey` in `pkg/lapi/client_stream.go`). `handleStreamCache` GETs it first. Hit → skip LAPI, hydrate Range membership, return. Miss → SET then GET `/v1/decisions/stream`. Best-effort, not SET NX. Shared Redis (session prefix) is how several bouncer processes skip duplicate polls in one interval.

**Lease duration**: `leaseDuration := c.updateInterval - 1`; if `< 1`, floor to `1`. `c.updateInterval` is `Config.UpdateIntervalSeconds`, validated `>= 1` (`requiredInt1`). Upstream stored `updateInterval - 1` with no floor, so interval 1 yielded TTL 0.

**Zero TTL**: in-tree local cache calls `golang-ttl-map` `Heap.Set`, which returns without storing when `ttl == 0` (`vendor/github.com/leprosus/golang-ttl-map/map.go`). Redis `SET … EX 0` is invalid. Either way the next GET misses and every instance polls.

**This fork**: the floor is already in `handleStreamCache`. `TestHandleStreamCacheLeaseHitHydrates` pre-seeds the key with TTL 60 and never exercises interval 1 or the miss→store path.

```
handleStreamCache
  GET updated
    hit  ──► hydrate Range membership, return (no LAPI)
    miss ──► SET updated TTL max(updateInterval-1, 1)
             increment streamFetches
             GET /v1/decisions/stream
             apply New/Deleted, hydrate
```

## Decisions

- Add-tests only. Do not change the floor in `pkg/lapi/client_stream.go` unless a test cannot be honest without a one-line fix (not expected).
- Prove the miss path stores the lease when `updateInterval == 1`, then a second call is a lease hit and does not fetch LAPI again (`streamFetches` stays 1; mock LAPI hit count stays 1).
- In-memory `cache.Client` is enough. The bug is “TTL passed to Set is 0 so the key is absent”; memory exhibits that. Redis EX 0 is out of scope (requirement).
- Reuse `testStreamLAPI` in `pkg/lapi/session_test.go` (empty stream JSON, hit counter). Wire `crowdsecScheme/Host/Path/StreamRoute`, `httpClient`, `updateInterval=1` on a `newTestRangeClient` (or equivalent) Client.
- Put the test in `pkg/lapi/client_stream_test.go` next to the owner, not in `client_range_test.go` (that file’s lease test is hydrate-on-hit, a Range concern).
- Do not sleep to prove TTL expiry (flaky). Assert `Get(cacheTimeoutKey)` succeeds after the first miss path, and the second `handleStreamCache` does not increment `streamFetches`.
- Spec: new leaf under `core` / `plugin` / `lapi` for stream poll lease duration (connection spec is package/file ownership, not this guard). Propose will FindSpecHost.
- Usage packets already explain isolated cache Clients. No new Language this phase; “stream poll lease” stays ticket vocabulary until propose names the spec.

Measured this phase: read `pkg/lapi/client_stream.go`, `pkg/lapi/client_range_test.go`, `pkg/lapi/session_test.go` `testStreamLAPI`, `pkg/cache/cache.go` `localCache.set`, `vendor/github.com/leprosus/golang-ttl-map/map.go` TTL 0 early return. Did not run tests (explore does not implement).

## Open questions

- Q: Should tests cover Redis backend explicitly, or is in-memory cache enough to prove lease storage at interval 1?
  Decision: assumed — in-memory only. The failure is TTL 0 so Set is a no-op; `golang-ttl-map` exhibits that. Redis `SET EX 0` is a separate caller-error-surfacing note, out of scope.
  By: explore

- Q: Where does the interval-1 lease test live?
  Decision: assumed — new `pkg/lapi/client_stream_test.go` next to `handleStreamCache`. Reuse `testStreamLAPI`. Do not extend `TestHandleStreamCacheLeaseHitHydrates` (that case is hydrate-on-hit with a pre-seeded TTL 60).
  By: explore

- Q: Which spec host owns the lease-duration floor?
  Decision: assumed — new `core_plugin_lapi_*` leaf for stream poll lease (not `core_plugin_lapi_connection`, which is package layout). Propose runs FindSpecHost and may fold if a closer leaf exists.
  By: explore

- Q: Must the test wait for TTL expiry, or is “key present + second call skips LAPI” enough?
  Decision: assumed — no sleep. After miss path, `Get("updated")` must succeed and a second `handleStreamCache` must not increment `streamFetches`. Expiry of a 1s TTL is not this ticket.
  By: explore
