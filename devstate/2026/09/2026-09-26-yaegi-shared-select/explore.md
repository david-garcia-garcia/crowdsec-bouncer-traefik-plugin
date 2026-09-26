# Explore
IssueKey: 2026-09-26-yaegi-shared-select
Verdict: in progress

## Concepts

Stream and metrics both enter one helper, `startTicker` (`pkg/lapi/client.go`). That helper starts one goroutine whose `select` waits on that call’s `ticker.C` and a buffered `stop`. `work()` runs on that goroutine (live `core_plugin_lapi_stream-single-flight`). Sleep and Close call `stopTicker` on `streamStop` and `metricsStop`, then nil those fields. Wake and `startStream` start them again.

```
New / startStream / Wake
        │
        ├─ startTicker("stream")  ──►  for { select { ticker.C → handleStreamTicker
        │                                              stop     → Stop+return } }
        └─ startTicker("metrics") ──►  for { select { ticker.C → handleMetricsTicker
                                                       stop     → Stop+return } }

Sleep / Close ──► stopTicker(streamStop); stopTicker(metricsStop)
```

yaegi v0.16.1 `_select` allocates `[]reflect.SelectCase` once per **statement** and the exec closure mutates that slice. Two goroutines that run the same `startTicker` select can wait on each other’s channels. `rangeChan` allocates a new case list per execution. Master tip `fcb76d1` is byte-identical. Outside fact: `knowledge/research/ext_yaegi_interp_select-cases/`.

**Units**

| Name | Path | Job |
| --- | --- | --- |
| `startTicker` | `pkg/lapi/client.go` | One goroutine: select on ticker + stop; run `work()` |
| `stopTicker` | `pkg/lapi/client.go` | Non-blocking send on that stop chan |
| Stream start | `pkg/lapi/client_stream.go` `startStream` | First stream ticker |
| Metrics start | `pkg/lapi/client.go` `New` | First metrics ticker when interval > 0 |
| Wake | `pkg/lapi/client.go` | Restart stream and/or metrics tickers after Sleep |
| Sleep / Close | `pkg/lapi/client.go` | Signal both stops; Close also drains metrics and idle HTTP |

**Call sites** (root `pkg/lapi`, patterns `startTicker(` / `stopTicker(`): **4** `startTicker` + **4** `stopTicker` = **8**. No other `pkg/` hits.

- `startTicker`: `client_stream.go:38` (`startStream`); `client.go:180` (`New` metrics); `client.go:249` (`Wake` stream); `client.go:254` (`Wake` metrics).
- `stopTicker`: `client.go:201–202` (`Close`); `client.go:229–230` (`Sleep`).
- Definitions: `stopTicker` `client.go:304`; `startTicker` `client.go:314`.

**Reproduce:** not reproduced at runtime. `yaegi` on PATH is the v0.16.1 module (`github.com/traefik/yaegi@v0.16.1`; `yaegi version` prints `devel`; hash matches `go install …@v0.16.1`). Native `go run` and `yaegi` of `repro_shared_select.go` (two shared-select tickers, 800 ms) stayed isolated (`fast≈40` / `slow≈4`). `repro_channel_share.go` (upstream 20_000-send shape, `GOMAXPROCS=2`, NumCPU=20) printed `isolated=true` under **both** native and yaegi. Native `go test` of that isolation is not evidence of the yaegi bug. PR 399’s own rate is rare (13_178 crosses in 5.1 M; ~1000× rarer at `GOMAXPROCS=1`). Source still owns the share: `ext_yaegi_interp_select-cases`. Implement writes the yaegi test that must fail on one shared select.

**Outside facts:** `knowledge/research/ext_yaegi_interp_select-cases/`. Upstream writes: issue 377 (stream GET stalls ~one or two metrics intervals; metrics POST continues); PR 399 (range `runTicker`, drop stop, return `*time.Ticker`, test `Test_runTicker_keepsEachTickerOnItsOwnChannel`).

Usage packets `core_plugin_lapi_stream-single-flight` and `core_plugin_lapi_usage-metrics` already say how to start/stop the helper. No Language gap. Usage gotcha for shared `_select` waits for the apply (devdocsimpact).

## Decisions

- Seam: keep `stopTicker` and the buffered stop. Split the loop into **two source functions** (`startStreamTicker` / `startMetricsTicker`, or two equivalently distinct bodies) so each `select` is its own statement and gets its own `_select` `cases` slice. `work()` stays on that goroutine. Sleep/Close still `stopTicker` then nil.
- Rejected: copy PR 399 (`for range ticker.C`, drop stop, return `*time.Ticker`) — Out of scope; `Ticker.Stop` does not close `C`, so the goroutine stays blocked after Sleep/Close.
- Rejected: one function that ranges the ticker and still `select`s on stop — that remaining `select` is still one shared statement.
- Rejected: keep one `startTicker` body — same statement, shared `cases`.
- Live contract: **fold**, not new, not skip. Leaves that already name `startTicker`: `openspec/specs/core_plugin_lapi_stream-single-flight` (`work()` on the ticker goroutine; MUST NOT add a new select-plus-timer **loop** — two copies of the existing helper are not a third poll loop) and `openspec/specs/core_plugin_lapi_usage-metrics` (Sleep/Wake/Close use the same helper). Propose MODIFIED those two. Do not add a third ticker leaf. Do not write the spec folder here.
- Isolation test: `pkg/lapi/zzz_ticker_own_channel_test.go` (zzz_ house style). Name may follow `Test_startTicker_keepsEachTickerOnItsOwnChannel` (upstream reference, not required). It calls production helpers. It **must fail under yaegi** with one shared select and **pass** after the two-function split. Drive: two loops, own channels, 20_000 sends, `GOMAXPROCS>1` (PR 399 shape).
- Yaegi proof path: `yaegi test` on package `lapi` (`-run` that test) and/or `pkg/yaegitest.Run` if a snippet is required so root `make yaegi_test` is not the only gate. Native `go test ./pkg/lapi` is **in addition**: Sleep/Close stop (natively observable). Native isolation of the same test is a false green for the yaegi bug — it is not the proof.

## Open questions

- Q: What loop shape is yaegi-safe and still stops when Sleep/Close call stopTicker?
  Rank: bounded asked — 8 existing startTicker/stopTicker call sites in pkg/lapi, all migratable here; Desired names a yaegi-safe ticker loop that still stops on Sleep/Close
  Decision: resolved — two distinct function bodies, each `select` on that loop’s `ticker.C` and buffered stop; `stopTicker` unchanged; `work()` stays inline on the ticker goroutine. Do not range-without-stop.
  By: propose

- Q: Where does the isolation test live, and how does it fail under yaegi with the shared select and pass with the fix?
  Rank: additive asked — new test this change creates; Desired names coverage that each loop receives only its own ticks
  Decision: resolved — `pkg/lapi/zzz_ticker_own_channel_test.go` calling production helpers; yaegi must see the shared-select failure and the two-function pass (upstream name is a reference only).
  By: propose

- Q: Is native go test in addition to the yaegi isolation test?
  Rank: additive asked — Desired names test coverage; Unknowns ask whether native go test can show the race
  Decision: resolved — yes, native tests for Sleep/Close stop. Native isolation is not proof of the yaegi bug (20_000-send harness was isolated under `go run`).
  By: propose

- Q: Live contract or no live contract for each loop staying on its own channel and Sleep/Close still stopping them?
  Rank: additive asked — Desired names an OpenSpec change for that runtime promise
  Decision: resolved — fold into `core_plugin_lapi_stream-single-flight` and `core_plugin_lapi_usage-metrics`. Not `none — no live contract`. Not a new ticker leaf.
  By: propose
