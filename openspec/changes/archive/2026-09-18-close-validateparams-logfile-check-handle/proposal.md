## Why

`validateLogging` opens `LogFilePath` to prove writability and assigns the `*os.File` to `_`, so a successful `ValidateParams` keeps that descriptor. `plugin.New` already holds the process-lifetime file from `logger.NewWithFormat`; the extra check handle is leftover, not the log owner.

## What Changes

- Close the independent writability-check file after a successful `OpenFile` in `validateLogging`. Keep the check; do not reuse `sharedLogFiles` and do not skip the open when the logger already opened the path.
- Add hunt-named regression coverage in the existing configuration test file that calls `ValidateParams` only.
- No public JSON/YAML key change. Not **BREAKING**.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: a successful writable-path check does not retain the check descriptor.

## Impact

- `pkg/configuration/configuration.go` (`validateLogging`)
- `pkg/configuration/zzz_configuration_test.go` (`TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck`)
- Out of scope: `NewWithFormat` reuse, `ResetSharedLogFilesForTest` / `sharedLogFiles` reclaim, other `ValidateParams` helpers, log rotation, operator-facing log path keys
