# Explore
IssueKey: 2026-09-06-upstream-377-stream-poll-freeze

## Concepts

**Stream poller (this process):** `lapi.Client.startStream` starts a ticker via `startTicker`. Each tick does `go handleStreamTicker()` → `handleStreamCache` → `crowdsecQuery` `GET /v1/decisions/stream`. Metrics uses a separate ticker and `reportMu` so only one usage-metrics POST runs at a time. Owner: `pkg/lapi/client.go`, `pkg/lapi/client_stream.go`.

**Cache lease `updated`:** `handleStreamCache` GETs key `updated`. Hit → hydrate Range membership, return `nil` (treated as poll success). Miss → SET TTL `updateInterval-1` (min 1s) then call LAPI. The lease is the multi-instance Redis skip (`core_cache_client_isolated-store`), not an in-process single-flight lock.

**One stream session:** Reclaim already shares one `lapi.Client` per LAPI URL+key (`core_plugin_middleware_instance-reclaim`). That stops a second *ticker from a second middleware*. It does not stop overlapping `handleStreamTicker` goroutines on that same Client (`go work()` per tick plus `Wake()` extra `go handleStreamTicker()`).

**CrowdSec cursor:** LAPI stores `stream_cursor` on the bouncer row (hashed key + IP LAPI sees). Two concurrent `startup=false` GETs on that row race the cursor (`ext_crowdsec_lapi_stream-cursor`).

**Reclaim:** Traefik `New` ctx is the holder. `Sleep` stops tickers; `Wake` restarts them and fires an extra poll (`startup=false`). Grace is 30s (`std_go_reclaim`). Do not add `sync.Once`.

```
  startTicker (never waits)
       │  go work()
       ▼
  handleStreamTicker ──┐
  Wake extra goroutine ─┼──► handleStreamCache
  startStream first ────┘         │
                    GET "updated"
                    hit → return nil (success)     // can mask in-flight fail
                    miss → SET lease → GET /stream // second miss = second GET
```

## Decisions

- Keep `go work()` on `startTicker`. Making work synchronous would re-block the ticker on a hung LAPI call (the reporter’s ~20 min silence while metrics still posted).
- Serialize in-process stream polls with **TryLock skip**, same job as `reportMu` but non-blocking. A skip is not success: do not reset `updateFailure` or force healthy.
- Redis sibling lease-hit stays success (another instance owns the poll). TryLock first so an in-process overlap never reaches that lease-as-success path.
- Do not encode 20 minutes. Bound each `crowdsecQuery` with the existing `HTTPTimeoutSeconds` (request context deadline). Native Go already honors `http.Client.Timeout`.
- Do not change metrics ticker behavior, reclaim Open/Sleep/Wake wiring, or Redis multi-instance SET NX.
- Tests live in `pkg/lapi`: overlapping Wake/ticker must yield one in-flight GET; in-process skip must not clear failures; timeout must bound `crowdsecQuery`.

## Reproduction

Throwaway `go test -count=1 -timeout 30s -v -run TestRepro_ ./pkg/lapi/` on this worktree (deleted after; not committed). Native Go, not Yaegi.

- Overlap while first GET held: 8 extra `handleStreamTicker` during an in-flight poll → **1** stream GET (lease already SET). Those extras returned success without waiting. **Lease-mask reproduced.**
- Concurrent `handleStreamCache` after deleting `updated`: **2** stream GETs, **8** nil returns. **Overlapping miss + lease-as-success reproduced.**
- `http.Client.Timeout = 1s` against a 3s handler: `crowdsecQuery` returned in ~1.00s with `context deadline exceeded (Client.Timeout exceeded while awaiting headers)`. **Timeout bounds in native Go.** No nil-`res` panic (`||` short-circuits).
- ~20 minute freeze: **not reproduced.** Needs a stall that ignores `Client.Timeout` (Yaegi timer or TCP blackhole) plus a ticker that waits on work.

## Recommended shape (for propose)

1. `streamPollMu sync.Mutex` on `Client`. `handleStreamTicker` `TryLock`; unlock after `handleStreamCache`. Failed TryLock returns without touching health/failure.
2. Keep `startTicker` `go work()` and `Wake()` extra poll; TryLock makes the extra a no-op when a poll is running.
3. `crowdsecQuery`: `context.WithTimeout` from `HTTPTimeoutSeconds` on the request. Guard `res` before reading status (defense if Do returns both).
4. Spec delta on `core_plugin_middleware_instance-reclaim`: one in-flight `handleStreamCache` per Client, not only one ticker per session. Skip-if-busy is not a successful poll.
5. Usage: one gotcha on `core_plugin_middleware.md` after apply (do not spawn overlapping stream polls; TryLock skip is not healthy).

## Open questions

- Q: What maps to the reporter’s exact ~20 minute gap with no `handleStreamCache:updated` lines?
  Decision: assumed — native Go already bounds `crowdsecQuery` with `http.Client.Timeout`. The gap matches a ticker blocked on work (upstream sync ticker, or Yaegi not firing the timer) plus a transport stall, not a product constant. Do not bake 20 minutes. Keep `go work()`, TryLock skip, and a request context deadline.
  By: explore

- Q: TryLock skip or mutex-wait single-flight?
  Decision: assumed — TryLock skip. Waiting would queue `go work()` goroutines behind a hung poll. Skip must not count as success. Redis lease-hit after owning the slot still counts as success.
  By: explore

- Q: Add `context.WithTimeout` when `http.Client.Timeout` already works in native Go?
  Decision: assumed — yes. One request deadline from `HTTPTimeoutSeconds`. Cheap, testable, and covers Do paths that might otherwise hang after headers. Do not add Yaegi-specific workarounds.
  By: explore

- Q: Who already owns visitor identity on this path?
  Decision: resolved — this change does not set client address, user, tenant, or Host. Stream polls are process-to-LAPI. Visitor IP stays `pkg/ip.GetRemoteIP` on ServeHTTP.
  By: explore
