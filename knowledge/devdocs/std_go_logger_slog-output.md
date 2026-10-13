# NewWithFormat slog output

## Language

**NewWithFormat**:
The constructor that builds the process slog logger: level, destination, JSON vs common handler, and the `component` attribute.
_Avoid_: slog.New at call sites; a per-router logger factory

**component**:
The slog attribute `NewWithFormat` stamps on every plugin logger. The value is `CrowdsecBouncer`.
_Avoid_: CrowdsecBouncerTraefikPlugin; CrowdsecBounder; the HTML template name as a second logger identity; User-Agent `traefik_plugin`

## Overview

Call `logger.NewWithFormat` once in plugin `New`. JSON is case-insensitive. Any other format uses the text/common handler. A non-empty writable `LogFilePath` reuses one process-lifetime file per cleaned path.

## How to use

- Construct via `NewWithFormat(logLevel, logFilePath, logFormat)`. Do not call `slog.New` for the process logger.
- Keep `component` as `CrowdsecBouncer`. Do not restore `CrowdsecBouncerTraefikPlugin`. Do not use `CrowdsecBounder`.
- Pass `"json"` (any case) for JSON. Anything else is common/text.
- Pass empty `logFilePath` for stdout. A writable path reuses the shared file. An unwritable path warns and falls back to stdout.
- Nest identity with `log.With` after construction (`std_go_logger_nested`). Request-path Trace stays on that child (`std_go_logger_debug-attrs`).

## Pattern snippet

```go
log := logger.NewWithFormat(config.LogLevel, config.LogFilePath, config.LogFormat)
```

## Key files

- `pkg/logger/logger.go` — `NewWithFormat`, `ReplaceAttr`, shared files
- `plugin.go` — process logger construction

## Gotchas

- Raw slog JSON without this package's `ReplaceAttr` prints Trace as `DEBUG-4`. Product `NewWithFormat` prints `TRACE`.
- Operators filtering `component=CrowdsecBouncerTraefikPlugin` miss new logs.
