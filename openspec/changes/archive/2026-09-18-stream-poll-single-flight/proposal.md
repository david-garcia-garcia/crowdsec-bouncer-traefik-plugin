## Why

On DestBranch the stream ticker starts a new goroutine every interval and never waits for the last poll. Three Client fields that decide `startup=` and whether cache-miss traffic is a LAPI failure are written and read with no synchronization. The `updated` lease does not serialize those writes. A Traefik reload already `Wake`s while a previous GET can still be in flight. CI never runs the race detector.

## What Changes

- Guard `handleStreamTicker` with a skip-if-busy `int64` in-flight flag (`CompareAndSwapInt64` enter, `defer StoreInt64` release). Covers the ticker, `startStream`'s async first poll, and `Wake`. Drop a busy tick; do not queue.
- Publish `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, and `updateFailure` as `int64` fields via `atomic.LoadInt64` / `atomic.StoreInt64`. Do not hold `Client.mu` across the HTTP poll. Do not use `atomic.Pointer[T]`, `atomic.Bool`, or `atomic.Int64`.
- Remove `go` from `startTicker` so `work()` runs on the ticker goroutine. Keep the existing `select` on `ticker.C` / buffered `stop`.
- Test-only: synchronize `TestSleepDrainsMetrics` body capture so `pkg/lapi` can be race-clean.
- Add overlap tests that fail on today's master and pass after.
- Add a second GitHub Actions job that runs `go test -race -count=1 ./pkg/...` with `CGO_ENABLED: 1`.

## Capabilities

### New Capabilities

- `core_plugin_lapi_stream-single-flight`: intra-instance skip-if-busy on the stream poll, plus atomic publish of startup/healthy/failure for the request path.
- `build_ci_github_race-detector`: a CI job that runs the Go race detector on `./pkg/...`.

### Modified Capabilities

None.

## Impact

- `pkg/lapi/client.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`
- `pkg/lapi/zzz_metrics_test.go` (test harness only)
- `pkg/lapi/zzz_client_stream_overlap_test.go` (new)
- `pkg/lapi/zzz_session_test.go`, `pkg/lapi/zzz_scopeunion_test.go`, `pkg/lapi/zzz_client_stream_log_test.go` (atomic loads / int64 literals)
- `.github/workflows/main.yml`
- Usage `knowledge/devdocs/core_plugin_lapi_stream-lease.md` and `knowledge/devdocs/core_plugin_lapi_connection.md` after apply (devdocsimpact)
- No **BREAKING** public JSON/YAML keys
- Out of scope: lease `Acquire` / `updated` / TTL, `pkg/bouncer`, `pkg/cache`, `pkg/configuration`, captcha, appsec, reclaim, a queueing mutex, a new `select`+timer loop, `-race` on the root suite, changing the workflow `push` trigger from `main` to `master`
