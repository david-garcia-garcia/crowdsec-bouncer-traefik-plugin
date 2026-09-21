# Explore
IssueKey: 2026-09-18-stream-poll-single-flight

## Concepts

DestBranch `b42860f` stream poll is three spawn sites into one unsynchronized `handleStreamTicker`:

```
startTicker (go work every ticker.C)
startStream  go handleStreamTicker  when LapiStreamStartupBlock=false
Wake         go handleStreamTicker  after restarting the ticker
```

`Client.mu` is lifecycle (`closed`, `sleeping`, stop channels) plus live header-scope registry. It is not the poll lock. Holding it across `crowdsecQuery` would stall `Sleep`, `Close`, and `registerLiveHeaderScopes`.

The `updated` lease (`core_plugin_lapi_stream-lease`) is an inter-instance / inter-process GET lock on a shared DecisionStore. It is not an intra-instance poll lock. TTL is `max(updateInterval-1, 1)`, so a poll longer than that window can win again. A lease loser still writes `isCrowdsecStreamStartup = false` (`client_stream.go:80`).

Three fields have no publication: `isCrowdsecStreamStartup`, `isCrowdsecStreamHealthy`, `updateFailure`. `streamFetches` is already `int64` + `atomic.AddInt64` / `LoadInt64`. `transport` / `rangeMembership` / `lastRangeIndex` are `atomic.Value`. No `atomic.Bool`, `atomic.Int64`, or `atomic.Pointer[T]` field exists. Yaegi v0.16.1 forbids `atomic.Pointer[T]` as a struct field (`core_plugin_lapi_connection`). `interp._select` can lose a timer wake (`std_go_reclaim`); reclaim uses `time.AfterFunc`. Do not add a second `select`+timer loop.

Reclaim: Traefik `New` ctx is the holder (`std_go_reclaim`, `core_plugin_middleware`). Last holder `Sleep`s (signals stop, does not wait for in-flight HTTP). Open during 30s grace `Wake`s the same Client. That is the stock overlap: previous GET (HTTP timeout default 10s) can still be running when `Wake` spawns again. Do not add `sync.Once` or a package global.

Request-path reader is `StreamHealthy()` (`pkg/lapi/client.go`). `pkg/bouncer` calls it on stream/alone cache miss. Fence: do not edit `pkg/bouncer`.

```
ticker.C / startStream / Wake
        │
        ▼
 handleStreamTicker   ← needs skip-if-busy (CAS int64)
        │
        ├─ lease Acquire (unchanged)
        ├─ GET /v1/decisions/stream
        └─ write startup / healthy / updateFailure   ← need atomic Load/Store
                │
                ▼
         StreamHealthy / streamQuery   (request path, other goroutine)
```

**Reproduced** (Docker `golang:1.22.12`, `CGO_ENABLED=1`, `-mod=vendor`, dest code):

1. Test-harness: `TestSleepDrainsMetrics` — handler write of `*gotBody` vs `waitMetricsBody` / `processedValue` read (`zzz_metrics_test.go:169` / `:423` / `:292`). Not production.
2. Production: `TestOpenStream_SleepingIntervalChangeWakesSameSlot` — test read of `isCrowdsecStreamStartup` vs `Wake` → `handleStreamCache` write (`client_stream.go:80`, spawned at `client.go:225`).

No active OpenSpec change. FindSpecHost (propose): new `core_plugin_lapi_stream-single-flight` (not a small adjustment to `stream-lease`); new `build_ci_github_race-detector` (not module-path). Do not change the lease leaf.

## Decisions

- Skip-if-busy on `handleStreamTicker` with a dedicated `int64` in-flight field and `atomic.CompareAndSwapInt64(0, 1)`, `defer atomic.StoreInt64(0)` so panic releases. CAS is required; Load-then-Store has a race window. This is `sync/atomic` on `int64`, same family as `streamFetches`, not the `atomic.Int64` type the owner declined.
- Cover all three spawn sites by putting the guard inside `handleStreamTicker` (not only `startTicker`).
- Remove `go` from `startTicker` so `work()` runs on the ticker goroutine. Existing `select` on `ticker.C` / buffered `stop` stays. Metrics ticker inherits that serialization.
- Publish the three flags as `int64` + `LoadInt64` / `StoreInt64`. `StreamHealthy` loads. `streamQuery` loads. Tests that read the fields load. Do not hold `mu` across HTTP.
- Do not queue ticks. Do not add a timer/`select` loop. Do not change `Acquire` / `updated` / TTL floor.
- Test-harness: synchronize `TestSleepDrainsMetrics` body capture (`atomic.Value` or mutex). Label it test-only in the PR.
- New overlap tests in `pkg/lapi/zzz_client_stream_overlap_test.go`. Keep the three lease tests unchanged.
- Second CI job, `CGO_ENABLED: 1`, `go test -race -count=1 ./pkg/...`. Do not `-race` the root suite. Note (do not fix) push trigger `main` vs default `master`.
- Propose change name: `stream-poll-single-flight`.

## Open questions

- Q: Who already owns identity (visitor address, stream health, reclaim lifetime)?
  Decision: assumed — visitor address stays `pkg/ip` / bouncer (fenced, unused here). Stream health is `Client.StreamHealthy`; this change only publishes the existing field. Reclaim lifetime is `*lapi.Client` on the existing table; do not add a second key or `sync.Once`.
  By: explore

- Q: How is skip-if-busy implemented without `atomic.Bool` / `atomic.Int64` / `TryLock` / a queueing mutex?
  Decision: resolved — `int64` field + `CompareAndSwapInt64` enter / `StoreInt64` release in `defer`. Same `sync/atomic` API as `streamFetches`. Ticket's Load/Store rule applies to the three published flags; CAS is the only race-free skip.
  By: explore

- Q: Does removing `go` from `startTicker` also serialize metrics POSTs?
  Decision: resolved — yes, accepted. One helper; ticket decided the `go` removal. A slow metrics POST delays the next metrics tick only, not stream (separate ticker goroutine).
  By: explore

- Q: Fold the intra-instance guard into `core_plugin_lapi_stream-lease`?
  Decision: resolved — no. Lease stays inter-instance `Acquire`. New leaf `core_plugin_lapi_stream-single-flight`. CI job is `build_ci_github_race-detector`, not `build_ci_github_module-path`.
  By: explore

- Q: Are other `pkg/` packages race-clean?
  Decision: assumed — run `go test -race ./pkg/...` in Docker after the lapi fix. Trivial test-harness races of the same kind get fixed; otherwise list exclusions in the PR. Do not silently narrow the job.
  By: explore
