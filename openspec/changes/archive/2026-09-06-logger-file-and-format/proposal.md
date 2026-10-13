## Why

Traefik middleware reload creates a new logger per `NewWithFormat` call. File-backed loggers open `LogFilePath` and never close, leaking descriptors. Log format matching is case-sensitive so `"JSON"` silently produces text logs while operators expect structured JSON.

## What Changes

- Share one process-lifetime open file per cleaned `LogFilePath` inside `pkg/logger` so repeated `NewWithFormat` calls do not accumulate descriptors.
- Select JSON handler when format equals `"json"` case-insensitively; all other values keep common/text handler.
- Unit tests for shared file reuse and uppercase JSON output via `NewWithFormat`.
- **Not BREAKING.** Public function signatures unchanged.

## Capabilities

### New Capabilities

- `std_go_logger_slog-output`: Process-lifetime file output sharing and case-insensitive JSON format selection for slog loggers.

### Modified Capabilities

None.

## Impact

- `pkg/logger/logger.go`, `pkg/logger/logger_test.go`
