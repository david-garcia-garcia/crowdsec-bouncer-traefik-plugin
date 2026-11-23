## Purpose

Defines the plugin slog logger's output destination and format when constructed via `NewWithFormat`.

## Requirements

### Requirement: Logs go to stdout only

Every logger constructed via `NewWithFormat` SHALL write to stdout. The plugin MUST NOT open, create, or append to a log file. Tests MAY redirect loggers built afterwards with `logger.SetOutputForTest`; production code MUST NOT call it.

#### Scenario: Default destination

- **WHEN** `NewWithFormat` is called outside a `SetOutputForTest` window
- **THEN** the logger writes to stdout

### Requirement: Case-insensitive JSON format

When the format argument equals `"json"` case-insensitively, the logger SHALL use a JSON slog handler with string level names (`TRACE`, `DEBUG`, `INFO`, `WARN`, `ERROR`) and the `component` attribute.

#### Scenario: Uppercase JSON format

- **WHEN** `NewWithFormat` is called with format `"JSON"`
- **THEN** log output is valid JSON with `"level":"INFO"` (or equivalent level string) for an info message

#### Scenario: Common format default

- **WHEN** `NewWithFormat` is called with format `"common"` or any value other than json (case-insensitive)
- **THEN** log output uses the text/common slog handler

### Requirement: slog component is CrowdsecBouncer

Every logger constructed via `NewWithFormat` SHALL include attribute `component` equal to `CrowdsecBouncer`. JSON and common formats SHALL both carry that value. The value MUST NOT be `CrowdsecBouncerTraefikPlugin`.

#### Scenario: JSON logger component

- **WHEN** `NewWithFormat` is called with format `"json"`
- **THEN** a log record includes attribute `component` equal to `CrowdsecBouncer`

#### Scenario: Common logger component

- **WHEN** `NewWithFormat` is called with format `"common"`
- **THEN** a log record includes `component=CrowdsecBouncer`
