## Why

`go test -race ./pkg/lapi/` fails on DestBranch with no PR applied, so the `Race detector` job is a coin flip on every PR. The session tests point a `slog` JSON handler at a plain `bytes.Buffer` and then read `logBuf.String()`, while the goroutine `New` spawns at `client.go:148` is still logging into that same buffer. `bytes.Buffer` is not safe for concurrent use, and `slog`'s handler serializes only its own work, not the writer's. Reproduced twice on `389a33b` (2 of 20 Docker race runs), with a different test blamed each time. Nothing in production shares a `bytes.Buffer` between goroutines: there the writer is a file. This change is test-only.

## What Changes

- Add one mutex-guarded log sink to the `pkg/lapi` test helpers. `Write` and the read take the same mutex, and tests read through the sink instead of touching `bytes.Buffer`.
- Convert every `bytes.Buffer` + `slog` capture site in the package, not only the two tests observed failing.
- Stop the `Client` before reading the log in the tests that open a real one, which also ends a leaked metrics ticker that currently outlives the test.
- No assertion removed or weakened; no production file changed.

## Capabilities

### New Capabilities

- `std_go_test_log-sink`: how an in-repo test captures `slog` output when the code under test logs from its own goroutines.

### Modified Capabilities

None.

## Impact

- `pkg/lapi/zzz_logsink_test.go` (new)
- `pkg/lapi/zzz_session_test.go`
- `pkg/lapi/zzz_client_stream_log_test.go`
- `knowledge/devdocs/std_go_test_log-sink.md` after apply (devdocsimpact)
- No production `.go` file, no public JSON/YAML key, no **BREAKING** change
- Out of scope: production code of any kind, the `Race detector` job itself, the workflow `push` trigger on `main` vs `master`, `pkg/bouncer`, `pkg/cache`, `pkg/configuration`, appsec, captcha, reclaim
