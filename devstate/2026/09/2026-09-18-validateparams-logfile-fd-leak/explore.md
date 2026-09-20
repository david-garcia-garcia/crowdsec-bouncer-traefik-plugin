# Explore
IssueKey: 2026-09-18-validateparams-logfile-fd-leak

## Concepts
`validateLogging` is a startup writability check, not the owner of the process log file. On a non-empty `LogFilePath` it `OpenFile`s append/create/write and assigns the `*os.File` to `_`. Successful `ValidateParams` therefore keeps that descriptor.

`plugin.New` already opened the same cleaned path via `logger.NewWithFormat` → `logOutput` / `sharedLogFiles`. That map is the process-lifetime owner (one file per path). It is not a `pkg/reclaim` value. `std_go_reclaim` / `core_plugin_middleware` bind LAPI and AppSec to Traefik `New` ctx; do not put this check handle on the reclaim table and do not add `sync.Once` or a new package global.

Logger and validation are not the same job. `NewWithFormat` falls back to stdout and warns when the path is not writable. `ValidateParams` is the hard fail that refuses the constructor. The check must stay an independent `OpenFile`; the defect is only that the handle is discarded.

Hunt name `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` is not in the tree. Existing `ValidateParams` cases cover log level (including alone + bad level) and never set `LogFilePath`. `std_go_logger_slog-output` forbids extra FDs from repeated `NewWithFormat` only.

```
plugin.New
  ├─ logger.NewWithFormat  → sharedLogFiles OpenFile (held)
  └─ ValidateParams
       └─ validateLogging  → OpenFile assigned to _ (leaked)
```

**Reproduced (Windows, this machine).** Throwaway probe (OS temp, not in the product tree) against dest code:

- Control: `OpenFile` without `Close`, then `Remove` → FAIL file-in-use.
- Control: `Close` then `Remove` → OK.
- `ValidateParams` with a temp `LogFilePath`, no logger file map, then `Remove` → FAIL file-in-use.
- `NewWithFormat` + `ValidateParams` + `ResetSharedLogFilesForTest` then `Remove` → FAIL file-in-use (the leftover handle is the check open, not the logger map).

Existing `go test ./pkg/configuration/ ./pkg/logger/` → pass (they do not assert this close).

## Decisions
- Close the writability-check file after a successful open. Keep the independent `OpenFile`. Do not reuse `sharedLogFiles` and do not skip the check when the logger already opened the path.
- Do not touch logger process-lifetime reclaim (`ResetSharedLogFilesForTest` / `sharedLogFiles`) unless implement discovers the close is impossible without it (not expected).
- Regression test: hunt function name in existing `pkg/configuration/zzz_configuration_test.go`. Call `ValidateParams` only (no `NewWithFormat`) so `Remove` / fd scan isolates the check handle.
- Propose adds a `core_plugin_middleware_config-validation` scenario that a successful writable-path check does not retain the descriptor. Do not change `std_go_logger_slog-output`.
- No new `knowledge/devdocs` packet: Close after a check is not a subsystem. No research folder: Windows `Remove` file-in-use was measured here; it is not a vendor API implementers would look up later.

## Open questions
- Q: Close the check handle or reuse the logger handle?
  Decision: resolved — close the check handle after a successful `OpenFile`. `ValidateParams` does not hold the logger file. Reuse would couple configuration to `sharedLogFiles` or skip the hard-fail check that the logger's stdout fallback does not perform.
  By: explore

- Q: Who owns the process-lifetime log file this check must not duplicate?
  Decision: resolved — `pkg/logger` `sharedLogFiles` (one `*os.File` per cleaned path). Not reclaim. Not `validateLogging`. The Traefik `New` context is the reclaim holder for LAPI/AppSec only. Do not propose `sync.Once` or a new package global for this close.
  By: explore

- Q: Should `ValidateParams` skip the `OpenFile` when `NewWithFormat` already opened the path?
  Decision: resolved — no. Logger warns and uses stdout on an unwritable path; `ValidateParams` must still return an error so `plugin.New` fails.
  By: explore

- Q: Where does the hunt-named regression test live?
  Decision: resolved — `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in existing `pkg/configuration/zzz_configuration_test.go`. Do not add a new test file.
  By: explore

- Q: How does the test prove the handle is closed on Linux CI, where `Remove` can succeed while the file is still open?
  Decision: assumed — Windows `Remove` after successful `ValidateParams` is the hunt proof (measured file-in-use on this host). On Linux, after `ValidateParams` scan `/proc/self/fd` and assert no descriptor still names the temp path. Skip the leak assertion only when neither Windows nor `/proc/self/fd` is available; still assert `ValidateParams` succeeds.
  By: explore

- Q: What if `Close` fails after a successful open?
  Decision: assumed — ignore the `Close` error; writability is already proven. Same discard as the logger `LoadOrStore` loser close.
  By: explore

- Q: Which spec leaf records the close invariant?
  Decision: resolved — add a scenario on `core_plugin_middleware_config-validation` (ValidateParams already requires a writable log file path). Do not change `std_go_logger_slog-output`.
  By: explore
