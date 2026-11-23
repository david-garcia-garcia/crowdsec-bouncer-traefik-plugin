# NewWithFormat slog output

## Language

**NewWithFormat**:
The constructor that builds the process slog logger: level, destination, JSON vs common handler, and the `component` attribute.
_Avoid_: slog.New at call sites; a per-router logger factory

**component**:
The slog attribute `NewWithFormat` stamps on every plugin logger. The value is `CrowdsecBouncer`.
_Avoid_: CrowdsecBouncerTraefikPlugin; CrowdsecBounder; the HTML template name as a second logger identity; User-Agent `traefik_plugin`

## Overview

Call `logger.NewWithFormat` once in plugin `New`. JSON is case-insensitive. Any other format uses the text/common handler. Output is always stdout; there is no log-file setting.

## How to use

- Construct via `NewWithFormat(logLevel, logFormat)`, or `New(logLevel)` for common format. Do not call `slog.New` for the process logger.
- Keep `component` as `CrowdsecBouncer`. Do not restore `CrowdsecBouncerTraefikPlugin`. Do not use `CrowdsecBounder`.
- Pass `"json"` (any case) for JSON. Anything else is common/text.
- Do not add a file destination. Rotation and shipping belong to Traefik's or the container runtime's log handling.
- Tests that read log lines call `logger.SetOutputForTest(w)` before building the logger and run the returned restore in `t.Cleanup`. Loggers built earlier keep their writer. Root-package tests use `newTestLogFile`, which redirects to a temp file.
- Nest identity with `log.With` after construction (`std_go_logger_nested`). Request-path Trace stays on that child (`std_go_logger_debug-attrs`).

## Pattern snippet

```go
log := logger.NewWithFormat(config.LogLevel, config.LogFormat)
```

## Key files

- `pkg/logger/logger.go` — `NewWithFormat`, `ReplaceAttr`, `SetOutputForTest`
- `pkg/logger/debounce.go` — `Debounced`, `ResetDebounceForTest`
- `plugin.go` — process logger construction

## Gotchas

- Raw slog JSON without this package's `ReplaceAttr` prints Trace as `DEBUG-4`. Product `NewWithFormat` prints `TRACE`.
- `logger.Debounced(log, level, interval, msg, attrs...)` emits `msg` at most once per `interval`. The caller passes that duration. The key is the message text, process-wide, so attributes do not open a new window. Tests that assert the line call `logger.ResetDebounceForTest` first. The stored time is an `atomic.Value`, not `atomic.Pointer[T]`: Yaegi v0.16 imports this package and cannot select that field.
- Operators filtering `component=CrowdsecBouncerTraefikPlugin` miss new logs.
