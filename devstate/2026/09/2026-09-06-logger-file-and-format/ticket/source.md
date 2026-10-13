# Log file descriptor leaked on every NewWithFormat; JSON format match is case-sensitive

## Problem
`pkg/logger.NewWithFormat` opens `LogFilePath` and never closes the file. Each Traefik middleware init/reload leaks an FD. `logFormat` only matches exact `"json"`; `"JSON"` (and the plugin uppercases other fields) silently gets text format.

## Evidence
Sibling findings: log-file-handle-leak, log-format-case-sensitive.

## Current behavior
File logger leaks FDs. Operators setting JSON with different casing get text logs with no error.

## Desired
Own and close (or process-lifetime wrap) the log file so reloads do not leak FDs. Treat log format case-insensitively (or document and validate one canonical value). Tests for file open/close (or documented process-lifetime handle) and `"JSON"`/`"json"` selecting JSON.

## Out of scope
Validation-time file open in `pkg/configuration` (separate). slog concurrency.
