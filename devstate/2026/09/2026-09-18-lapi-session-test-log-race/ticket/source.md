# Ticket source: stop the `pkg/lapi` session tests racing on their log buffer

Scratch source for the ticket. Copy to `ticket/source.md` in the bus folder and delete this file
from the repository root.

Suggested key: `2026-09-18-lapi-session-test-log-race`.

This is a **test-only** fix. No production code path is at fault and none should change.

## The problem, in one line

`go test -race ./pkg/lapi/` fails on `master` about half the time, so the `Race detector` CI job that
#72 added is a coin flip on every PR.

Measured on `master` `389a33b`, four consecutive Docker race runs: clean, race, race, clean.

## Proof, and the exact race

```
WARNING: DATA RACE
Write at 0x00c00053c720 by goroutine 750:
  bytes.(*Buffer).tryGrowByReslice()
  bytes.(*Buffer).Write()
  log/slog.(*commonHandler).handle()
  log/slog.(*JSONHandler).Handle()
  log/slog.(*Logger).Error()
  lapi.(*Client).handleMetricsTicker()      pkg/lapi/client_metrics.go:76
  lapi.New.gowrap1()                        pkg/lapi/client.go:148

Previous read at 0x00c00053c720 by goroutine 739:
  bytes.(*Buffer).String()
  lapi.TestOpenStream_TLSOnlyAdoptsTransport()   pkg/lapi/zzz_session_test.go:416

Goroutine 750 (running) created at:
  lapi.New()                     pkg/lapi/client.go:148
  lapi.OpenStream.func1()        pkg/lapi/session.go:113
  reclaim.(*Table).put.func1()   vendor/.../reclaim/table.go:435
  reclaim.runHook()              vendor/.../reclaim/table.go:176
  reclaim.(*Table).OpenWithHooks()
  lapi.OpenStream()              pkg/lapi/session.go:112
  lapi.TestOpenStream_TLSOnlyAdoptsTransport()   pkg/lapi/zzz_session_test.go:398
```

The tests install a `slog` logger whose writer is a plain `bytes.Buffer`, then assert on
`logBuf.String()`. `OpenStream` reaches `lapi.New` through the reclaim table's open hook, so the
client's background tickers are running before the assertion. Nothing stops them, so the metrics
ticker is still logging into that buffer while the test reads it. `bytes.Buffer` is not safe for
concurrent use, and `slog`'s handler serializes only its own work, not the writer's.

In production the writer is a file, so this specific race does not exist there. Do not "fix" any
production code for it.

## Two things that will mislead you, read these before starting

1. **The blamed test changes between runs.** The victim is whichever test is reading the buffer when a
   leaked ticker logs. Observed as `TestOpenStream_TLSOnlyAdoptsTransport` on one tree and
   `TestOpenStream_LiveMetricsMismatchSharesSilently` on `master`. Do not treat the name in a failure
   as *the* broken test.
2. **It always passes in isolation.** `-run TestOpenStream_TLSOnlyAdoptsTransport -race` is reliably
   green, because no earlier test has leaked a ticker yet. Reproduce with the **whole package**, and
   repeat: a single clean run proves nothing at roughly even odds.

## Scope

`bytes.Buffer` plus `slog` appears in `pkg/lapi/zzz_session_test.go` (about 15 hits, of which
`TestClient_LifecycleLogs:143`, `TestOpenStream_LiveMetricsMismatchSharesSilently:168` and
`TestOpenStream_TLSOnlyAdoptsTransport:381` are the ones that construct a real client) and in
`pkg/lapi/zzz_client_stream_log_test.go` (2 hits). Check every site, not only the three that have been
observed failing; any of them can be the next victim.

## Deliverables

**1. A concurrency-safe log sink for tests.** Wrap the buffer so `Write` and the read are both under
one mutex, and have the tests read through that wrapper instead of touching `logBuf.String()`. Keep it
in one place in the package's test helpers rather than repeating a mutex per test. This alone removes
the race regardless of goroutine lifetimes.

**2. Stop the client before asserting.** The tests already hold what they need to close the session.
Ending the tickers before reading the log also removes a goroutine leak that currently spans the whole
package run, and which can mask or cause other flakes. Do this even though deliverable 1 already fixes
the reported race: leaked tickers logging into a shared sink are a bug in their own right.

Prefer not to reduce coverage: if a test asserts on a log line the ticker emits, keep asserting it, but
read the sink after the client is stopped.

## How to prove it

The bar is repetition, not a single green run.

- Before: run `docker run --rm -v ${PWD}:/src -w /src -e CGO_ENABLED=1 golang:1.22.12 go test -race
  -count=1 ./pkg/lapi/` repeatedly on unmodified `master` until you have seen it fail at least twice,
  and record which test was blamed each time.
- After: the same command **at least ten consecutive times** with no `WARNING: DATA RACE` anywhere in
  the output. Grep the output for `DATA RACE` rather than trusting the exit code alone.
- Also confirm the tests still assert what they used to: no assertion may be deleted to make the race
  go away.

Then the usual gates: `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test .
-count=1`, and `golangci-lint run ./...` with `C:\Program Files\Git\usr\bin` on `PATH` so `goimports`
finds `diff`.

## Constraints

- Base off current `master` `389a33b`. Do not merge or close any PR, and do not touch the open ones.
- The main checkout has uncommitted and untracked work in it, including `AGENT-WORKLOG.md` and five
  notes under `knowledge/debt/`. Work in a worktree and leave the main checkout alone.
- Yaegi v0.16.1 constrains production code, but this is test-only, so that does not bind here. Still
  keep to the package's existing test idiom.
- Open a PR against `master` and stop. Do not merge it: the owner merges.

## Related

`knowledge/debt/2026-09-18-lapi-session-tests-race-on-shared-log-buffer.md` holds the same analysis and
should be deleted by this ticket once the fix lands, since the note exists only to describe an unfixed
problem.

Note that `master` never runs the race job itself: the push triggers target the stale `main` branch,
see `knowledge/debt/2026-09-18-release-pipeline-targets-stale-main.md`. The flake is only ever seen
through PR checks, which is part of why it went unnamed for three sessions.
