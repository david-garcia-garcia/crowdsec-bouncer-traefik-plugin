## Context

See `proposal.md` Why. Dest `startTicker` is one `select` on `ticker.C` and a buffered stop; stream and metrics both enter it (`pkg/lapi/client.go`, `client_stream.go`). `stopTicker` is a non-blocking send; Sleep and Close call it then nil the fields. yaegi v0.16.1 `_select` allocates `[]reflect.SelectCase` once per statement (`knowledge/research/ext_yaegi_interp_select-cases/`). Native isolation of a 20_000-send harness is not evidence of that share.

FindSpecHost:

```
verdicts:
  - { deltaId: stream-ticker-own-select, fold, spec-id: core_plugin_lapi_stream-single-flight, confidence: high, candidates: [core_plugin_lapi_stream-single-flight, core_plugin_lapi_connection, core_plugin_lapi_stream-apply] }
  - { deltaId: metrics-ticker-own-select, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_stream-single-flight] }
```

Search: family `core_plugin_lapi`. Leaves that already name `startTicker` are `stream-single-flight` (`work()` on the ticker goroutine; MUST NOT add a new select-plus-timer loop) and `usage-metrics` (Sleep/Wake/Close use the same helper). Small adjustment (one–three requirements) → fold, not a new ticker leaf. `connection` is HTTP+auth. `stream-apply` is payload apply. `std_go_reclaim_context-lease` is constructor-context reclaim, not this select. No in-flight change delta yet. Cleanup/absence-only → not this job.

## Goals / Non-Goals

**Goals:**

- Two distinct `select` statements, one per ticker loop, each waiting on that loop’s tick channel and buffered stop.
- `work()` stays on the ticker goroutine.
- Sleep/Close still end both loops through `stopTicker`.
- A yaegi v0.16.1 test fails on one shared `select` and passes after the split.

**Non-Goals:**

- Copying PR 399 (`for range ticker.C`, drop stop, return `*time.Ticker`).
- A third ticker spec leaf.
- Changing stream GET, usage-metrics POST, or reclaim beyond ticker stop.
- Treating native `go test` isolation as proof of the yaegi bug.

## Decisions

1. **Two source functions, each with its own `select`.** `startStreamTicker` / `startMetricsTicker` (or two equivalently distinct bodies). Each loop: `for { select { ticker.C → work(); stop → Stop+return } }`. Alternative: keep one `startTicker` — rejected (same statement, shared `cases`). Alternative: one function that ranges the ticker and still `select`s on stop — rejected (remaining `select` is still shared). Alternative: PR 399 `for range ticker.C` — rejected; `Ticker.Stop` does not close `C`, and this fork signals stop from Sleep/Close.
2. **Injectable tick+stop on those bodies so the isolation test can send 20_000 values.** Unexported `runStreamTicker` / `runMetricsTicker` (each owns one `select`) taking `<-chan time.Time`, stop, and `work`. Wrappers `NewTicker`, buffered stop, `defer ticker.Stop()`, spawn the matching run. Tests in `pkg/lapi` call the run functions. Alternative: only real `time.Ticker` intervals — rejected (cannot drive 20_000 sends). Alternative: a shared wrapper that contains the `select` — rejected (yaegi keys `_select` by statement).
3. **`stopTicker` unchanged.** Non-blocking send. Sleep/Close still call it then nil `streamStop` / `metricsStop`. Wake / `New` / `startStream` call the matching start function.
4. **Isolation test** `pkg/lapi/zzz_ticker_own_channel_test.go` (zzz_ house style). Name may follow `Test_startTicker_keepsEachTickerOnItsOwnChannel`. Two loops, own channels, 20_000 sends, `GOMAXPROCS>1` (PR 399 shape). It MUST fail under yaegi v0.16.1 against one shared `select` and pass after the split. Call production helpers, not a test-only loop.
5. **Yaegi is the proof path.** Run `yaegi test` on package `lapi` (`-run` that test) and/or `pkg/yaegitest.Run` so root `make yaegi_test` (`yaegi test -v .`) is not the only gate. Native `go test ./pkg/lapi` is additional coverage for Sleep/Close stop (`TestSleepDrainsMetrics` / `TestCloseDrainsMetrics` plus a dedicated stop if those do not observe the goroutine exit).

## Risks / Trade-offs

- [Duplicated loop bodies drift] → Keep the two `select` bodies adjacent and symmetrical (same steps, same names for the same roles). Do not extract a helper that contains the `select`.
- [The share is rare (PR 399: ~13k crosses in 5.1M)] → Use the 20_000-send, `GOMAXPROCS>1` harness; do not shrink it to a timing test.
- [Native `go test` of the same harness stays isolated] → Document that green native isolation is a false green for the yaegi bug; gate on yaegi.
- [Root `make yaegi_test` does not interpret `pkg/lapi`] → Tasks name `yaegi test` on that package and/or `pkg/yaegitest.Run`.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert of the two function bodies to one `startTicker`.
