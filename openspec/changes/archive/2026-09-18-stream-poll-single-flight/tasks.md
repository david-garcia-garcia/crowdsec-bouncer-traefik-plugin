## 1. Production single-flight and atomics

- [x] 1.1 Change `isCrowdsecStreamStartup` and `isCrowdsecStreamHealthy` to `int64`; publish all three flags with `atomic.LoadInt64` / `StoreInt64` / `AddInt64`; add `streamPollInFlight`
- [x] 1.2 Guard `handleStreamTicker` with CAS enter and `defer` release (panic-safe)
- [x] 1.3 Load the flags in `StreamHealthy` and `streamQuery`; do not hold `Client.mu` across HTTP
- [x] 1.4 Remove `go` from `startTicker` so `work()` runs on the ticker goroutine
- [x] 1.5 Update in-package tests that construct or read the old bool fields

## 2. Test-harness race (test-only)

- [x] 2.1 Synchronize `TestSleepDrainsMetrics` / `newUsageMetricsClient` body capture so the mock handler and the test reader do not race

## 3. Overlap tests

- [x] 3.1 Slow poll longer than the interval: at most one in-flight, fetches do not climb one per tick
- [x] 3.2 Two overlapping `handleStreamTicker` calls with a still-valid lease: one fetch
- [x] 3.3 Concurrent `StreamHealthy()` while a poll writes
- [x] 3.4 `Sleep` then `Wake` while a poll is in flight: at most one GET
- [x] 3.5 Keep `TestHandleStreamCacheIntervalOneStoresLease`, `TestHandleStreamCache_TwoMemoryPollersOneFetch`, and the Redis twin green

## 4. CI race job

- [x] 4.1 Add a second job on `.github/workflows/main.yml` with `CGO_ENABLED: 1` that runs `go test -race -count=1 ./pkg/...` (Go 1.22, same checkout path). Do not add `-race` to the root suite

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
- [x] 5.2 Docker `go test -race -count=1 -mod=vendor ./pkg/lapi/` silent after the fix
