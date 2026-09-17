# Requirement
IssueKey: 2026-09-06-logger-file-and-format

## Problem
`NewWithFormat` opens a log file when `LogFilePath` is set and never closes it; Traefik middleware init/reload accumulates file descriptors. `logFormat` matches only lowercase `"json"`, so values like `"JSON"` silently produce text logs.

## Current (code)
- `pkg/logger/logger.go:44-47` — `os.OpenFile` assigns `output = logFile` with no `Close` in the package.
- `pkg/logger/logger.go` — no `Close` helper or lifecycle hook for file-backed loggers.
- `pkg/logger/logger.go:83-87` — JSON handler only when `logFormat == "json"`; all other strings use text handler.
- `plugin.go:25-26` — `LogLevel` uppercased; `LogFormat` passed through unchanged to `NewWithFormat`.
- `pkg/logger/logger_test.go:38-75` — `TestJSONLogFormat` builds a handler manually; does not call `NewWithFormat`.
- `pkg/logger/logger_test.go:145-156` — `TestInvalidLogFile` checks fallback, not file lifecycle or FD count.
- `bouncer_logging_test.go:218-219` — integration tests use lowercase `"json"` only; no case-variant or close coverage.

## Desired
- Close (or document and wrap for process lifetime) the log file opened by `NewWithFormat` so reloads do not leak FDs; add unit test for open/close or documented lifetime handle.
- Match log format case-insensitively (e.g. `"JSON"` selects JSON); add unit test on `NewWithFormat` for uppercase JSON output.

## Affected
- `pkg/logger/logger.go`, `pkg/logger/logger_test.go`
- Call site: `plugin.go:26` (consumes logger; may need cleanup hook if `Close` is exposed)

## Out of scope
- `pkg/configuration/configuration.go:391` validation-time file open without close (separate package).
- Undocumented format strings such as `text` (current fall-through to common handler).
- slog handler concurrency semantics.
- Normalizing `LogLevel` when callers bypass `plugin.go`.

## Unknowns
- Whether Traefik/Yaegi exposes a middleware shutdown hook to invoke logger cleanup on reload, vs. relying on process-lifetime shared file handle.

## Tensions
- Ticket asks for explicit close on reload vs. alternative “open once per process and share writer” — both satisfy FD leak; explore must pick one.
- Exposing `Close()` on logger return type may require plugin/bouncer wiring not named in ticket.
