# Requirement
IssueKey: 2026-09-18-lapi-session-test-log-race

## Problem
`go test -race ./pkg/lapi/` fails on `master` `389a33b` without any PR applied, so the `Race detector` job #72 added is a coin flip on every PR. The session tests point a `slog` JSON handler at a plain `bytes.Buffer` and then assert on `logBuf.String()`, while the background metrics goroutine `lapi.New` starts (reached from `OpenStream` through the reclaim table's open hook) is still logging into that same buffer. `bytes.Buffer` is not safe for concurrent use and `slog`'s handler serializes only its own work, not the writer's. This is **test-only**: in production the writer is a file. Two traps: the blamed test name moves between runs (the victim is whoever reads the buffer when a live ticker logs), and the failure never reproduces with `-run <name>` in isolation.

## Current (code)
- `TestClient_LifecycleLogs` builds `var logBuf bytes.Buffer`, wraps it in `slog.NewJSONHandler`, and reads `logBuf.String()`. `pkg/lapi/zzz_session_test.go:144` `:155`
- `TestOpenStream_LiveMetricsMismatchSharesSilently` does the same at `LevelDebug` and constructs a real client through `OpenStream`. `pkg/lapi/zzz_session_test.go:178` `:203`
- `TestOpenStream_TLSOnlyAdoptsTransport` does the same at `LevelInfo` and constructs a real client through `OpenStream`. `pkg/lapi/zzz_session_test.go:390` `:416`
- `captureTestStreamTickLog` builds `var buf bytes.Buffer` and returns `buf.String()` after `fn`. `pkg/lapi/zzz_client_stream_log_test.go:38` `:40`
- `New` starts the metrics work immediately with `go client.handleMetricsTicker()` and then a 1s metrics ticker (`testStreamConfig` passes `metricsInterval` 1). `pkg/lapi/client.go:148` `:149`
- `handleMetricsTicker` logs at ERROR on a failed POST; `reportMetrics` also logs at DEBUG on every call. `pkg/lapi/client_metrics.go:76` `:265`
- `OpenStream` reaches `New` inside the reclaim open hook. `pkg/lapi/session.go:112` `:113`
- No test in `pkg/lapi` stops the `Client` it opened: the three `OpenStream` sites above pass `context.Background()`, so only `t.Cleanup(reclaim.ResetForTest)` ends the client, after the assertions.
- `Client.Close` stops both tickers, drains metrics synchronously, and is idempotent. `pkg/lapi/client.go:161`
- `reclaim.ResetForTest` → vendored `Table.Reset` → `Sleep` then `dispose`/`Close` per slot; `Client.Sleep` spawns `go c.drainMetrics()`, which logs after the test body returned. `pkg/reclaim/default.go:55` `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/reclaim/table.go:752`
- House rule: in-repo test files are `zzz_*_test.go` (`openspec/specs/std_go_test_zzz-prefix`, `knowledge/devdocs/std_go_test_zzz-prefix.md`).

## Desired
- One mutex-guarded log sink in the package's test helpers. `Write` and the read both take the same mutex. Every test reads through the wrapper instead of touching `bytes.Buffer.String()`.
- Every `bytes.Buffer` + `slog` site in `pkg/lapi` tests uses that sink, not only the three observed failing tests.
- The tests that construct a real client stop it before they read the log, which also ends a goroutine leak that currently spans the package run.
- No existing assertion deleted or weakened. A test that asserts on a line the ticker emits keeps asserting it, read after the client is stopped.

## Affected
- `pkg/lapi/zzz_logsink_test.go` (new helper)
- `pkg/lapi/zzz_session_test.go`
- `pkg/lapi/zzz_client_stream_log_test.go`
- `openspec/specs/std_go_test_*` (spec host for the house rule)
- `knowledge/devdocs/std_go_test_*` (usage packet, after apply)

## Out of scope
- Any production file. If a production race is found, report it; do not fix it here.
- The `Race detector` CI job itself and the `push` trigger on `main` vs `master`.
- `pkg/bouncer`, `pkg/cache`, `pkg/configuration`, appsec, captcha, reclaim.
- Merging, closing, or commenting on the 11 open PRs.

## Unknowns
- Whether stopping the client removes every asynchronous writer (the ticker goroutine's deferred DEBUG line and `Sleep`'s `go drainMetrics` can still log), so whether deliverable 1 is load-bearing on its own.

## Tensions
- Ticket line numbers match dest `389a33b`.
- Yaegi v0.16.1 constrains production code only; this change is test-only.
- The captured trace in the ticket blames `TestOpenStream_TLSOnlyAdoptsTransport`; `master` also blames `TestOpenStream_LiveMetricsMismatchSharesSilently`. Neither name is *the* broken test.
