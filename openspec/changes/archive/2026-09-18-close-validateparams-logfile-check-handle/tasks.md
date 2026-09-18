## 1. Close the check handle

- [x] 1.1 In `validateLogging`, close the writability-check file after a successful `OpenFile`; ignore the `Close` error
- [x] 1.2 Keep the independent `OpenFile`; do not reuse `sharedLogFiles` and do not skip the check when the logger already opened the path

## 2. Regression test

- [x] 2.1 Add `TestHunt_ValidateParams_closesLogFileAfterWritabilityCheck` in `pkg/configuration/zzz_configuration_test.go`
- [x] 2.2 Call `ValidateParams` only (no `NewWithFormat`) with a temp writable `LogFilePath`
- [x] 2.3 After success: Windows `os.Remove` the temp path; Linux scan `/proc/self/fd` and assert no descriptor names that path; skip the leak assertion only when neither probe is available
- [x] 2.4 Assert `ValidateParams` still errors when `LogFilePath` is non-empty and not writable

## 3. Verify

- [x] 3.1 `go test ./pkg/configuration/`
