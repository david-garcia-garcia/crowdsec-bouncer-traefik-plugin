## Context

See `proposal.md` Why. Dest `master` `startTicker` does `go work()` (`pkg/lapi/client.go`). `startStream` (async first poll) and `Wake` also `go handleStreamTicker()`. Three flags are unsynchronized. `streamFetches` is already `int64` + `sync/atomic`. Yaegi v0.16.1 forbids `atomic.Pointer[T]` as a struct field and can lose a timer wake in `interp._select`. Reclaim `Sleep`/`Wake` does not wait for in-flight HTTP.

FindSpecHost:

```
verdicts:
  - { deltaId: intra-instance-stream-single-flight, fold|new: new, spec-id: core_plugin_lapi_stream-single-flight, confidence: high, candidates: [core_plugin_lapi_stream-lease, core_plugin_lapi_connection, core_plugin_lapi_stream-single-flight] }
  - { deltaId: ci-race-job, fold|new: new, spec-id: build_ci_github_race-detector, confidence: high, candidates: [build_ci_github_module-path, build_ci_github_race-detector] }
```

Search: family `core_plugin_lapi` leaves `stream-lease` (inter-instance `Acquire` / `updated`) and `connection` (replaceable transport). Intra-instance skip-if-busy plus request-path atomic flags is a new capability, not a one–three-requirement bugfix of the lease. Family `build_ci_github` leaf `module-path` is checkout path only; a race job is a new CI capability.

## Goals / Non-Goals

**Goals:**

- At most one in-flight `handleStreamTicker` per Client.
- Request-path `StreamHealthy` / `streamQuery` reads are race-free versus poller writes.
- `pkg/lapi` is silent under `go test -race`.
- CI runs that detector on `./pkg/...`.

**Non-Goals:**

- Changing the stream lease.
- Holding `Client.mu` across HTTP.
- `atomic.Pointer[T]`, `atomic.Bool`, `atomic.Int64` types.
- A queueing mutex or a new `select`+timer loop.
- Editing `pkg/bouncer`, `pkg/cache`, `pkg/configuration`.
- `-race` on `go test .`.
- Fixing the workflow `push` trigger (`main` vs `master`).

## Decisions

1. **Skip-if-busy inside `handleStreamTicker`.** `int64 streamPollInFlight` + `CompareAndSwapInt64(0, 1)` / `defer StoreInt64(0)`. Covers ticker, `startStream` async first poll, and `Wake`. Alternative: Load-then-Store — rejected (race window). Alternative: mutex that Locks — rejected (queues).
2. **Three flags are `int64` + `LoadInt64` / `StoreInt64`.** Mirror `streamFetches`. `StreamHealthy` loads. `streamQuery` loads. `updateFailure++` becomes `AddInt64`.
3. **Remove `go` from `startTicker`.** Work runs on the ticker goroutine. Metrics ticker inherits that. Buffered `stop` keeps `Sleep` non-blocking.
4. **Do not hold `mu` across `crowdsecQuery`.** Lifecycle + scope-union stay on `mu`.
5. **Test harness uses a mutex (or `atomic.Value`) around the captured usage-metrics body** in `TestSleepDrainsMetrics` / `newUsageMetricsClient`. Label it test-only.
6. **New overlap tests** in `zzz_client_stream_overlap_test.go`. Keep the three lease tests unchanged.
7. **Second workflow job**, not a step on `main`. `CGO_ENABLED: 1`, Go 1.22, same checkout path. `go test -race -count=1 ./pkg/...`.
8. **New spec leaves**, do not fold into `stream-lease` or `module-path`.

## Risks / Trade-offs

- [CAS is not named in the ticket's Load/Store sentence] → Ticket applies that to the three published flags. Skip-if-busy needs CAS; same `sync/atomic` `int64` API as `streamFetches`, not the `atomic.Int64` type.
- [Removing `go` serializes a slow metrics POST on the metrics ticker] → Accepted. Separate goroutine from stream.
- [Other `pkg/` packages may race] → Fix trivial test-harness races or list exclusions in the PR. Do not silently narrow the job.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert.
