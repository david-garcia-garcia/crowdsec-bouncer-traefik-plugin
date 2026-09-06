# Standards

## Identifier walk (Name for the scope)

| Identifier | Introduced / retargeted | Role in body | Verdict |
|------------|-------------------------|--------------|---------|
| `TestHandleStreamCacheIntervalOneStoresLease` | introduced (test func) | Job callers use: interval-one lease store + skip | pass — spells the job |
| `server` | introduced (local) | httptest LAPI mock from `testStreamLAPI` | pass |
| `hits` | introduced (local) | stream GET counter from `testStreamLAPI` | pass — matches helper contract |
| `parsed` | introduced (local) | `url.Parse` result; only `.Host` used for `crowdsecHost` | pass — transform suffix in the method that parsed; matches `session_test.go` co-user of `testStreamLAPI` |
| `err` | introduced (local) | standard Go error | pass |
| `lapiClient` | introduced (local) | LAPI client under test | pass — matches `client_range_test.go` |
| `cacheClient` | introduced (local) | isolated cache for lease assertions | pass — matches `newTestRangeClient` return |
| `got` | introduced (local) | comparison scratch in assertions | pass |
| `lapiClient.updateInterval` | retargeted | poll interval under test (1) | pass |
| `lapiClient.crowdsecScheme`, `crowdsecHost`, `crowdsecPath`, `crowdsecStreamRoute`, `crowdsecHeader`, `crowdsecKey`, `httpClient` | retargeted | wire mock LAPI endpoint into client | pass — field names are production roles |
| `cacheTimeoutKey` | referenced (pre-existing) | lease key `"updated"` | pass — not renamed by this diff |
| `core_plugin_lapi_stream-lease` | introduced (spec id) | stream poll lease TTL spec host | pass — FindSpecHost grammar |

Usage-doc Gotchas (`core_cache_client.md`): test consumes `newTestRangeClient`, which constructs a new `cache.Client` per call; no package-level map restored; no Redis prefix or migration touched. No **Do** breach.

1. [hard] Symmetry and consistency — `pkg/lapi/client_stream_test.go:35,45` — `testStreamLAPI` returns an atomically incremented hit counter; sibling consumer `session_test.go` reads with `atomic.LoadInt64(hits)` but this test dereferences `*hits`
   ```go
   if got := *hits; got != 1 {
   ```
   → Use `atomic.LoadInt64(hits)` (and import `sync/atomic`) like `TestOpenStream_LiveMetricsMismatchWarnsAndShares`
   Status: done
   Argument: atomic.LoadInt64(hits) in both assertions, matching session_test.go.
