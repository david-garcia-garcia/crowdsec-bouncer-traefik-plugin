# Config validation

## Language

**Config validation**:
The constructor hard-fail of the Traefik `*configuration.Config` `New` is about to use. Not the process-lifetime logger.
_Avoid_: sharedLogFiles, NewWithFormat stdout fallback, reclaim value

**Writability-check handle**:
The `*os.File` opened only to prove a non-empty `LogFilePath` is writable. Not the process-lifetime logger file.
_Avoid_: sharedLogFiles, reclaim value, log owner

## Overview

`ValidateParams` rejects a bad Config before `New` continues. `validateLogging` still `OpenFile`s a non-empty `LogFilePath` even when `logger.NewWithFormat` already holds that path. Close that handle after a successful open.

## How to use

- Keep the `LogFilePath` check as its own `OpenFile` (append/create/write). Do not reuse `sharedLogFiles` and do not skip the open when the logger already opened the path.
- After a successful open, `Close` the writability-check handle. Ignore the `Close` error; writability is already proven.
- Still return an error when the path is not writable. The logger's stdout fallback is a different job.

## Pattern snippet

```go
checkFile, err := os.OpenFile(filepath.Clean(config.LogFilePath), os.O_APPEND|os.O_CREATE|os.O_WRONLY, 0600)
if err != nil {
	return fmt.Errorf("LogFilePath is not writable %w", err)
}
_ = checkFile.Close()
```

## Key files

- `pkg/configuration/configuration.go` (`validateLogging`)
- `plugin.go` (`NewWithFormat` then `ValidateParams`)

## Gotchas

- `NewWithFormat` warns and uses stdout when the path is not writable. `ValidateParams` must still fail so `plugin.New` does not start.
- Do not put the writability-check handle on `pkg/reclaim` or add `sync.Once` / a package global for this close. `sharedLogFiles` is the process-lifetime owner.
