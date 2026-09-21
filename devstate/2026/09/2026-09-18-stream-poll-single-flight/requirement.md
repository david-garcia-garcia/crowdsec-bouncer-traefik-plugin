# Requirement
IssueKey: 2026-09-18-stream-poll-single-flight

## Problem
On master `b42860f8`, `startTicker` launches a new goroutine per tick and never waits for the previous one. Three `Client` fields (`isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, `updateFailure`) are written by that work and read from the request path with no synchronization. The stream lease does not prevent intra-instance overlap: it can expire before a slow poll finishes, and a lease loser still writes `isCrowdsecStreamStartup`. Overlapping polls can flap stream health (default `UpdateMaxFailure=0` then routes cache-miss traffic through `CrowdsecLapiFailureAction`, default `ban`) and can interleave range-blob apply. Three deliverables in one PR: the single-flight plus atomic flags; a test-only race fix in `TestSleepDrainsMetrics`; a CI job that runs the race detector.

## Current (code)
- `startTicker` does `go work()` on every `ticker.C`. `pkg/lapi/client.go`
- `startStream` with `StreamStartupBlock=false` does `go c.handleStreamTicker()` then starts the ticker. `pkg/lapi/client_stream.go`
- `Wake` starts the ticker then `go c.handleStreamTicker()`. `pkg/lapi/client.go`
- `handleStreamTicker` / `handleStreamCache` write `isCrowdsecStreamHealthy`, `updateFailure`, and `isCrowdsecStreamStartup` with no lock and no atomic. `pkg/lapi/client_stream.go`
- `StreamHealthy()` is a raw bool read. `pkg/lapi/client.go`
- `streamQuery` reads `isCrowdsecStreamHealthy` and `isCrowdsecStreamStartup` unlocked. `pkg/lapi/client_decisions.go`
- `Client.mu` guards `closed`, `sleeping`, ticker stop channels, and `liveHeaderScopes`. It is not held around the three flags or the HTTP poll. `pkg/lapi/client.go`
- `streamFetches` is already an `int64` published with `atomic.AddInt64` / `atomic.LoadInt64`. `pkg/lapi/client.go` `pkg/lapi/client_stream.go`
- `transport`, `rangeMembership`, and `lastRangeIndex` use `atomic.Value`. No `atomic.Bool` / `atomic.Int64` / `atomic.Pointer[T]` field in this package. `pkg/lapi/client.go`
- Stream lease `Acquire` on `updated` with TTL `max(updateInterval-1, 1)`. Loser hydrates Range and sets `isCrowdsecStreamStartup = false`. `pkg/lapi/client_stream.go` `knowledge/devdocs/core_plugin_lapi_stream-lease.md`
- `Sleep` and `Close` signal the buffered stop channel and do not wait for in-flight work. `pkg/lapi/client.go`
- `pkg/bouncer` calls `StreamHealthy()` on stream/alone cache miss. `pkg/bouncer/bouncer.go` (read-only; out of scope to change)
- `TestOpenStream_SleepingIntervalChangeWakesSameSlot` reads `isCrowdsecStreamStartup` after `Wake`. `pkg/lapi/zzz_session_test.go`
- `TestSleepDrainsMetrics` races `waitMetricsBody` / `processedValue` reading `*body` against the mock handler writing `*gotBody`. `pkg/lapi/zzz_metrics_test.go`
- `.github/workflows/main.yml` job `main` sets `CGO_ENABLED: 0`. No workflow step passes `-race`. Push trigger is `main`, not `master`.
- Existing lease tests: `TestHandleStreamCacheIntervalOneStoresLease`, `TestHandleStreamCache_TwoMemoryPollersOneFetch`, `TestHandleStreamCache_TwoRedisPollersOneFetch`. `pkg/lapi/zzz_client_stream_test.go`

## Desired
- Guard `handleStreamTicker` with a skip-if-busy in-flight flag, released on every path including panic. Cover ticker ticks, `startStream`'s async first poll, and `Wake`. Drop a busy tick; do not queue.
- Publish the three flags as `int64` fields via `atomic.LoadInt64` / `atomic.StoreInt64` (mirror `streamFetches`). Do not use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64`.
- Do not hold `Client.mu` across the HTTP call.
- Remove `go` from `startTicker` so `work()` runs on the ticker goroutine. Keep the existing `select` on `ticker.C` / `stop`. `stop` stays buffered.
- Fix `TestSleepDrainsMetrics` harness so `pkg/lapi` can be race-clean. Label it test-only in the PR.
- Add overlap tests that fail on today's master and pass after (slow poll, lease-valid overlap, concurrent `StreamHealthy()`, Sleep then Wake while in flight). Keep the three lease tests passing.
- Add a second CI job that runs `go test -race -count=1 ./pkg/...` with `CGO_ENABLED: 1`, Go 1.22, same checkout path as `main`. Do not add `-race` to the root suite. If other `pkg/` packages race, fix trivial test-harness races or list exclusions in the PR.
- Note (do not fix) that the workflow `push` trigger is `main` while the default branch is `master`.
- Supersedes #30 and #42; do not close them in this run.

## Affected
- `pkg/lapi/client.go`
- `pkg/lapi/client_stream.go`
- `pkg/lapi/client_decisions.go`
- `pkg/lapi/zzz_metrics_test.go` (test-harness only)
- `pkg/lapi/zzz_client_stream_test.go` and/or `pkg/lapi/zzz_client_stream_overlap_test.go`
- `pkg/lapi/zzz_session_test.go` if the raw `isCrowdsecStreamStartup` read must load atomically
- `.github/workflows/main.yml`
- `openspec/specs/core_plugin_lapi_stream-lease/spec.md` and/or a new intra-instance single-flight leaf (propose decides the fold)
- `knowledge/devdocs/core_plugin_lapi_connection.md` and `knowledge/devdocs/core_plugin_lapi_stream-lease.md` if usage text must name the in-flight guard and atomic flags

## Out of scope
- `pkg/bouncer`, `pkg/cache`, `pkg/configuration`, captcha, appsec, reclaim
- Changing the stream lease design (`Acquire` / `updated` / TTL floor)
- A mutex that queues ticks
- A new `for { timer; work() }` or second `select` on `ticker.C`
- `atomic.Pointer[T]`, `atomic.Bool`, `atomic.Int64` as struct fields
- Holding `Client.mu` across the HTTP poll
- Adding `-race` to `go test .`
- Changing the workflow `push` trigger from `main` to `master`
- Closing or rebasing #30 / #42
- Sibling PR #71 files: `pkg/ip`, `pkg/bouncer`, `pkg/configuration`, `README.md`

## Unknowns
- Whether `go test -race ./pkg/...` is clean outside `pkg/lapi` after the harness fix (CI job scope).
- Exact helper for in-flight counting in the new tests (reuse `testStreamLAPI` delay vs a custom handler).

## Tensions
- Ticket line numbers match dest `b42860f` (`startTicker` 247–255, `StreamHealthy` 306–308, `Wake` 225, `startStream` 41, lease 67–82).
- Ticket forbids touching `pkg/bouncer`; `StreamHealthy()` stays the request-path API. Atomic publish is on the LAPI fields.
- `startTicker` is also used for metrics. Removing `go` serializes a slow metrics POST on that ticker goroutine; ticket still decides it.
- Stream-lease spec and usage doc describe inter-instance `Acquire` only. Intra-instance skip-if-busy is a new invariant on the same poll path; propose must fold or add a leaf, not change the lease.
- No Task subagent is available in this session; prepare is written in-process. Note on the card.
