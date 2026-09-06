## 1. Interval-one lease test

- [x] 1.1 Add `TestHandleStreamCacheIntervalOneStoresLease` in `pkg/lapi/client_stream_test.go`: `updateInterval` 1, `testStreamLAPI`, miss path stores `updated`, `streamFetches` is 1
- [x] 1.2 Same test: second `handleStreamCache` keeps `streamFetches` at 1 (lease hit skips LAPI)

## 2. Verify

- [x] 2.1 `go test ./pkg/lapi/ -count=1 -run TestHandleStreamCache`
