# Requirement
IssueKey: 2026-09-18-validateparams-logfile-fd-leak

## Problem
`validateLogging` opens `LogFilePath` to check writability and discards the handle, so a successful `ValidateParams` keeps an extra descriptor. `plugin.New` already opened the same path via `logger.NewWithFormat`. Hunt proof name: `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` (Windows `Remove` fails file-in-use).

## Current (code)
- `plugin.New` builds the logger with `LogFilePath` before `ValidateParams`. `plugin.go:37-46`
- `logger.NewWithFormat` / `logOutput` open a process-lifetime shared file for a writable cleaned path. `pkg/logger/logger.go:32-37` `:88-115`
- `ValidateParams` always ends in `validateLogging`. `pkg/configuration/configuration.go:349`
- `validateLogging` on a non-empty `LogFilePath` calls `os.OpenFile` (append/create/write) and assigns the file to `_`. The handle is never closed. `pkg/configuration/configuration.go:500-505`
- Existing tests cover log level (including alone + bad level) and logger reuse; none assert the writability handle is closed. `pkg/configuration/zzz_configuration_test.go:106-110` `:149` `pkg/logger/zzz_logger_test.go:188-198`
- Hunt test `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` — not found
- Spec requires writable log file path at ValidateParams; logger spec covers `NewWithFormat` reuse only. `openspec/specs/core_plugin_middleware_config-validation/spec.md` `openspec/specs/std_go_logger_slog-output/spec.md`

## Desired
Close the file opened for the writability check (or reuse the logger handle) so successful `ValidateParams` does not retain an extra descriptor. Include a regression test. Bound to this defect.

## Affected
- `pkg/configuration/configuration.go`
- `pkg/configuration/zzz_configuration_test.go` (or the hunt-named test file if later phases add it)

## Out of scope
- Logger process-lifetime file reclaim (`ResetSharedLogFilesForTest` / shared map) unless the close-or-reuse fix requires it
- Changing `NewWithFormat` reuse semantics
- Other ValidateParams helpers (captcha, LAPI, AppSec, templates)
- Runtime log rotation or operator-facing log path keys

## Unknowns
- Hunt proof is a name, not an in-tree test
- Ticket line numbers `484-488` are stale; the open-and-discard is at `500-505` on dest HEAD

## Tensions
- Ticket offers close-the-check-handle or reuse the logger handle; `ValidateParams` does not hold the logger file today
- Logger spec already forbids extra FDs from repeated `NewWithFormat`; it does not mention the ValidateParams check open
