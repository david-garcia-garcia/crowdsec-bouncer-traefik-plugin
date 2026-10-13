## Context

See proposal.md for motivation. `plugin.New` opens `LogFilePath` through `logger.NewWithFormat` (`sharedLogFiles`, one `*os.File` per cleaned path) and then calls `ValidateParams`. `validateLogging` does its own `OpenFile` (append/create/write) and currently discards the handle. Logger and validation are different jobs: `NewWithFormat` warns and falls back to stdout when the path is not writable; `ValidateParams` is the hard fail that refuses the constructor.

## Goals / Non-Goals

**Goals:**
- Close the writability-check file after a successful open so a passing `ValidateParams` does not keep an extra descriptor.
- Keep the check as an independent `OpenFile` so an unwritable path still fails `ValidateParams`.
- Prove the close with the hunt-named test in the existing configuration test file.

**Non-Goals:**
- Reusing `sharedLogFiles` from configuration, or skipping the check when the logger already opened the path.
- Putting the check handle on `pkg/reclaim` or adding `sync.Once` / a new package global.
- Changing `NewWithFormat` reuse, `ResetSharedLogFilesForTest`, or `std_go_logger_slog-output`.
- A new `knowledge/devdocs` packet.

## Decisions

1. Close after a successful `OpenFile`. Alternative (reuse the logger file) rejected: `ValidateParams` does not hold that file, and reuse would couple configuration to `sharedLogFiles` or skip the hard-fail check the logger's stdout fallback does not perform.
2. Ignore the `Close` error after a successful open. Writability is already proven. Same discard as the logger `LoadOrStore` loser close.
3. Regression test `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in `pkg/configuration/zzz_configuration_test.go`. Call `ValidateParams` only (no `NewWithFormat`) so the assertion isolates the check handle.
4. Leak proof: Windows `os.Remove` after a successful `ValidateParams` (file-in-use when the handle is still open). On Linux, scan `/proc/self/fd` and assert no descriptor still names the temp path. Skip the leak assertion only when neither Windows nor `/proc/self/fd` is available; still assert `ValidateParams` succeeds.

## Risks / Trade-offs

- [Risk] Linux `os.Remove` can succeed while the file is still open → Mitigation: do not treat `Remove` as the Linux proof; use `/proc/self/fd`.
- [Risk] Implement discovers the close is impossible without touching the logger map (not expected) → Mitigation: explore allows that only if the close cannot land otherwise; do not pre-empt it.

## Migration Plan

None. Startup-only close. Rollback is revert the `validateLogging` close and the hunt test.
