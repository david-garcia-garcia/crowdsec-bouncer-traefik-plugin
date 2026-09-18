# Bring `pkg/appsec` and `pkg/logger` log capture onto the mutex-guarded sink

IssueKey: 2026-09-18-lapi-session-test-log-race
Size: large
Action: note

## Why this follow-up

`std_go_test_log-sink` now says an in-repo test that captures `slog` output SHALL read it through a mutex-guarded sink. `pkg/lapi` conforms after this change; two other packages still hand a bare `bytes.Buffer` to a handler and read `buf.String()`:

- `pkg/appsec/zzz_session_test.go` — `TestOpen_TimeoutOnlyAdoptsTransport` and `TestOpen_TLSOnlyAdoptsTransport`, both around a reclaimed `appsec.Client`
- `pkg/logger/zzz_logger_test.go` — three sites that assert on handler output

Neither is a flake today: the `appsec` client starts no ticker and no goroutine of its own, and the logger tests log from the test goroutine only. They are the same shape that made `pkg/lapi` a coin flip, and the `Race detector` job runs `./pkg/...`, so the day either component gains a background writer the gate goes flaky again with a test name that moves between runs.

## Why it was not taken

The ticket scoped this change to `pkg/lapi` and to a test-only diff, and asked for no production change and no widening. Converting two more packages would put unrelated files in a PR whose whole point is that it is small and provably green.

## Risks

A future component that logs from a goroutine turns one of these tests into the next moving-target flake, and the reader has to rediscover the mechanism from scratch. Cheap to prevent: each package gets the same `syncLogSink` helper, or one shared test helper package if the repo grows one.

## Context

Conforming shape: `pkg/lapi/zzz_logsink_test.go` (`syncLogSink`, `newTestLogSink`).
Usage: `knowledge/devdocs/std_go_test_log-sink.md`.
Spec: `openspec/specs/std_go_test_log-sink/spec.md`.
