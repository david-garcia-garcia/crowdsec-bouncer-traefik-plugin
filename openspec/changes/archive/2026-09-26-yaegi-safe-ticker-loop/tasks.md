## 1. Isolation test against the shared select

- [x] 1.1 Add `pkg/lapi/zzz_ticker_own_channel_test.go` (`zzz_` prefix). Name may follow `Test_startTicker_keepsEachTickerOnItsOwnChannel`. Call production loop helpers (not a test-only `select`). Drive two loops on own channels, 20_000 sends each, `GOMAXPROCS>1`
- [x] 1.2 Keep one shared `select` statement (current `startTicker`, or one extracted `runTicker` both loops still call). Do not split yet
- [x] 1.3 Prove fail under yaegi v0.16.1 (binary on PATH; Traefik/CI pin). From repo root, GOPATH as `pkg/yaegitest.GoPath` (module at `src/<ModulePath>`, vendored utilities copied): `yaegi test -v ./pkg/lapi -run Test_startTicker_keepsEachTickerOnItsOwnChannel`. If that package path cannot load imports, add a `TestYaegi_*` in the same file that calls `pkg/yaegitest.Run` with a snippet that starts the two production loops, then `go test ./pkg/lapi -count=1 -run TestYaegi_startTicker_keepsEachTickerOnItsOwnChannel` (skips when `yaegi` is not on PATH). Root `make yaegi_test` (`yaegi test -v .`) is not this gate. Native `go test ./pkg/lapi -run Test_startTicker_keepsEachTickerOnItsOwnChannel` staying green is not proof of the yaegi bug

## 2. Split the ticker loops

- [x] 2.1 Add `runStreamTicker` and `runMetricsTicker` in `pkg/lapi/client.go`, each with its own `select` on that loop’s tick channel and buffered stop; `work()` stays on that goroutine; no extra `go` per tick
- [x] 2.2 Add `startStreamTicker` / `startMetricsTicker` wrappers: `NewTicker`, buffered stop, `defer ticker.Stop()`, spawn the matching run, return stop. Delete the shared `startTicker` body. Do not `for range ticker.C`. `stopTicker` unchanged
- [x] 2.3 Point `startStream`, `New` metrics, `Wake` stream, and `Wake` metrics at the matching start function (four `startTicker` call sites)

## 3. Prove the split under yaegi and native stop

- [x] 3.1 Point the isolation test at the two production run functions. Confirm the same yaegi command from 1.3 now passes (shared-select fail from 1.3 is required; skip this if 1.3 was not a fail)
- [x] 3.2 Native `go test ./pkg/lapi -count=1` covering Sleep/Close stop (`TestSleepDrainsMetrics`, `TestCloseDrainsMetrics`, plus a dedicated stop of both ticker goroutines if those drain tests do not observe exit). Native isolation of 1.1 is additional coverage, not the yaegi proof
- [x] 3.3 Grep `pkg/lapi` (not tests) for a remaining shared `startTicker` `select` and for `for range` over ticker `C` — zero product hits
