## 1. Reproduce first

- [ ] 1.1 Docker `go test -race -count=1 ./pkg/lapi/` on unmodified DestBranch until it fails at least twice; record the blamed test each time

## 2. Concurrency-safe test log sink

- [ ] 2.1 Add `pkg/lapi/zzz_logsink_test.go` with `syncLogSink` (mutex around `Write` and `String`) and `newTestLogSink(level)`
- [ ] 2.2 Convert `TestClient_LifecycleLogs`, `TestOpenStream_LiveMetricsMismatchSharesSilently`, and `TestOpenStream_TLSOnlyAdoptsTransport` to read through the sink
- [ ] 2.3 Convert `captureTestStreamTickLog` in `zzz_client_stream_log_test.go` to the same sink

## 3. Stop the client before asserting

- [ ] 3.1 `Close()` the shared client in `TestOpenStream_LiveMetricsMismatchSharesSilently` before reading the log
- [ ] 3.2 `Close()` the shared client in `TestOpenStream_TLSOnlyAdoptsTransport` after the transport asserts and before reading the log
- [ ] 3.3 Confirm no assertion was deleted or weakened

## 4. Verify

- [ ] 4.1 Docker `go test -race -count=1 ./pkg/lapi/` at least ten consecutive times, grep for `DATA RACE`
- [ ] 4.2 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
- [ ] 4.3 Delete `knowledge/debt/2026-09-18-lapi-session-tests-race-on-shared-log-buffer.md`
