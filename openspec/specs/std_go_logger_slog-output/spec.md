## Purpose

Defines how the plugin slog logger selects output destination and format when constructed via `NewWithFormat`.

## Requirements

### Requirement: Shared log file per path

When `LogFilePath` is non-empty and writable, the logger package SHALL reuse one process-lifetime open file for each distinct cleaned path across all `NewWithFormat` calls. Repeated construction with the same path MUST NOT open additional file descriptors for that path.

#### Scenario: Reload reuses existing file

- **WHEN** `NewWithFormat` is called twice with the same writable `LogFilePath`
- **THEN** both loggers write to the same underlying open file without a second successful open for that path

#### Scenario: Unwritable path falls back

- **WHEN** `LogFilePath` is set but not writable
- **THEN** the logger writes to stdout and emits a warning (unchanged behavior)

### Requirement: Case-insensitive JSON format

When the format argument equals `"json"` case-insensitively, the logger SHALL use a JSON slog handler with string level names (`DEBUG`, `INFO`, `WARN`, `ERROR`) and the `component` attribute.

#### Scenario: Uppercase JSON format

- **WHEN** `NewWithFormat` is called with format `"JSON"` and empty file path
- **THEN** log output is valid JSON with `"level":"INFO"` (or equivalent level string) for an info message

#### Scenario: Common format default

- **WHEN** `NewWithFormat` is called with format `"common"` or any value other than json (case-insensitive)
- **THEN** log output uses the text/common slog handler
