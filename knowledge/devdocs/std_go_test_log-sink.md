## Language

**log sink**:
The `io.Writer` a test installs behind a `slog` handler so it can assert on what the code under test logged.
_Avoid_: "log buffer" — a bare `bytes.Buffer` is the shape this packet exists to prevent.

**leaked ticker**:
A background goroutine of a component a test started and never stopped, still logging into that test's sink after the assertion.

## How to use

- Build the logger with the package's sink helper, never with a `bytes.Buffer` you keep a reference to:

```go
log, sink := newTestLogSink(slog.LevelInfo)
client, err := Open(ctx, cfg, log, "first", "test")
...
client.Close()               // stop the tickers that log into sink
logged := sink.String()      // read only through the sink
```

- Read captured output with `sink.String()`. Both `Write` and `String` take the sink's mutex, so a goroutine you cannot join may keep logging while you read.
- Stop the component before the read. `Close()` on a `lapi.Client` stops the stream and metrics tickers, drains metrics synchronously, and is idempotent, so the later `t.Cleanup(reclaim.ResetForTest)` is a no-op rather than a `Sleep` that spawns another goroutine.
- Order assertions around the stop: read values the component owns (transport, fetch counts) before `Close`, and read the log after it. Do not drop an assertion because the timing moved.

## Pattern snippet

```go
type syncLogSink struct {
	mu  sync.Mutex
	buf bytes.Buffer
}

func (s *syncLogSink) Write(record []byte) (int, error) {
	s.mu.Lock()
	defer s.mu.Unlock()
	return s.buf.Write(record)
}
```

## Key files

- `pkg/lapi/zzz_logsink_test.go` — `syncLogSink` and `newTestLogSink` for that package
- `pkg/bouncer/zzz_logsink_test.go` — same helper in that package
- `pkg/lapi/zzz_session_test.go`, `pkg/lapi/zzz_client_stream_log_test.go` — callers

## Gotchas

- `bytes.Buffer` is not safe for concurrent use, and `slog`'s handler serializes only its own work, not the writer's. A handler with a bare buffer plus any background logger is a data race.
- `lapi.New` spawns `go client.handleMetricsTicker()` before it returns, and `Open` reaches `New` through the reclaim open hook. That goroutine cannot be joined from a test, so `Close()` alone does not make a bare buffer safe — the sink is what does.
- `slog` drops a `Debug` record before the writer when the handler level is `Info`, so a capture at `LevelDebug` has strictly more concurrent writers than one at `LevelInfo`. Do not conclude from a green `LevelInfo` test that the shape is safe.
- The failure this prevents blames a different test on each run and always passes under `-run <name>`, because the victim is whichever test reads while a live ticker logs. Reproduce with the whole package, repeatedly.
