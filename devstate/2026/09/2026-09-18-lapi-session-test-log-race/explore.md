# Explore
IssueKey: 2026-09-18-lapi-session-test-log-race

## Concepts

Four `bytes.Buffer` + `slog` capture sites exist in `pkg/lapi` tests. Every one of them is a potential victim, not only the three the ticket observed:

```
zzz_session_test.go:144  TestClient_LifecycleLogs                          Info   struct-literal Client, no tickers
zzz_session_test.go:178  TestOpenStream_LiveMetricsMismatchSharesSilently   Debug  real client via OpenStream
zzz_session_test.go:390  TestOpenStream_TLSOnlyAdoptsTransport             Info   real client via OpenStream
zzz_client_stream_log_test.go:38  captureTestStreamTickLog helper          param  struct-literal Client, no tickers
```

The writers that are live while a test reads its buffer, all reached from `New` / the reclaim hooks and none of them joinable from a test:

```
New (client.go:148)         go client.handleMetricsTicker()   ERROR on a failed POST     <- the observed writer
New (client.go:149)         metrics ticker, 1s in testStreamConfig
reportMetrics (:265)        DEBUG "reportMetrics: items=..."  only lands at LevelDebug
startTicker (client.go:253) defer log.Debug(name+"_ticker:stopped") after stop, LevelDebug only
Sleep (client.go:201)       go c.drainMetrics()               ERROR after the server is closed
```

`slog` `Logger.Debug` is dropped by `Handler.Enabled` before it reaches the writer, so the DEBUG writers above only race the `LevelDebug` test. The ERROR writers race every level.

Lifetime today: the three real-client tests pass `context.Background()` to `OpenStream`, so no holder ever goes away and nothing stops the tickers inside the test body. The client ends only at `t.Cleanup(reclaim.ResetForTest)`, which runs `Table.Reset` → `Sleep` hook → `dispose`/`Close` — and `Sleep` itself spawns `go c.drainMetrics()`, so even cleanup adds an asynchronous writer that outlives the test function.

**Reproduced** on unmodified `master` `389a33b` (Docker `golang:1.22.12`, `CGO_ENABLED=1`, `go test -race -count=1 ./pkg/lapi/`): 2 races in 20 runs, and the blamed test differed between them exactly as the ticket warns.

```
race run A  FAIL  TestOpenStream_LiveMetricsMismatchSharesSilently  read zzz_session_test.go:203
race run B  FAIL  TestOpenStream_TLSOnlyAdoptsTransport             read zzz_session_test.go:416
```

Both traces are the same shape: `Write ... bytes.(*Buffer).tryGrowByReslice` from `handleMetricsTicker` (`client_metrics.go:76`), goroutine created at `New` `client.go:148` via `OpenStream.func1` → `reclaim.(*Table).put.func1`; previous read `bytes.(*Buffer).String()` in the test. Nothing on the production side of that trace is unsynchronized — the shared object is the test's buffer.

Serial runs are much less likely to hit it than loaded ones: 8 serial runs were all clean, and both failures came from a 4-way parallel batch. That is consistent with the window being "a background ERROR log lands around the test's read".

FindSpecHost candidates: `std_go_test_zzz-prefix` (same family, but its unit is the test *filename*), `std_go_logger_slog-output` (production logger destination, not test capture), `core_plugin_lapi_*` (production behavior). No existing leaf owns "how an in-repo test captures log output". Verdict: `new`, `std_go_test_log-sink`, confidence high.

## Decisions

- One `syncLogSink` in a new `pkg/lapi/zzz_logsink_test.go`: `sync.Mutex` + `bytes.Buffer`, `Write` and `String` both under that mutex. One helper, not a mutex per test (ticket deliverable 1).
- A `newTestLogSink(level)` constructor returns the `*slog.Logger` and the sink, so a test cannot accidentally keep a raw buffer.
- Convert all four capture sites, including `captureTestStreamTickLog`, whose clients have no tickers today — the rule is the sink, not a per-test judgement about which goroutines exist.
- Stop the client before reading the log in the two tests that open a real one (ticket deliverable 2), via `Close()`, which stops both tickers, drains metrics synchronously, and is idempotent. `Close` before `t.Cleanup(reclaim.ResetForTest)` also short-circuits `Sleep`'s `go drainMetrics`, so the goroutine leak really ends.
- Keep every existing assertion, including `owner.StreamFetches()`, the `hits` counts, the transport asserts, and both negative log asserts. Read the sink after `Close`.
- Do not touch production code. The trace's production frames are a goroutine writing to a writer the test chose; the fix belongs to the test.

## Open questions

- Q: Does stopping the client remove every asynchronous writer, making deliverable 1 redundant?
  Decision: resolved — no. The writer in both captured traces is the goroutine `New` spawns at `client.go:148`; a test cannot join it, and `Close` does not wait for it. `Close` narrows the window and ends the leak; the mutex sink is what makes the read safe. Both are needed, as the ticket says.
  By: explore

- Q: Should `TestClient_LifecycleLogs` and `captureTestStreamTickLog` change, given their clients start no tickers?
  Decision: resolved — yes, convert them. They are the next victims if either helper ever builds a client through `New`, and the ticket asks for every site.
  By: explore

- Q: Does calling `Close()` inside the test invalidate what the tests assert?
  Decision: resolved — no. `Close` stops tickers, drains metrics (a POST to `/v1/usage-metrics`, which `testStreamLAPI` does not count as a stream hit), and closes idle HTTP. It does not clear `streamFetches`, the stored transport, or the reclaim binding, so `StreamFetches()`, `hits`, and `currentTransport()` keep their values.
  By: explore

- Q: Is there a production race behind this?
  Decision: resolved — none found in these traces. Every reported pair is (background goroutine writing the test's `bytes.Buffer`) vs (test reading it). Production writes to a `logger` file writer. Nothing to report to the owner beyond that.
  By: explore
