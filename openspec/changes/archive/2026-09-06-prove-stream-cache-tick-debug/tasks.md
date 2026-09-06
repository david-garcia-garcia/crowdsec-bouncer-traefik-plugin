## 1. Stream tick log tests

- [x] 1.1 Add `pkg/lapi/client_stream_log_test.go` with slog JSON buffer helpers at INFO and DEBUG
- [x] 1.2 Lease-miss: mock LAPI stream fetch, assert `handleStreamCache:updated` present at DEBUG and absent at INFO
- [x] 1.3 Lease-hit: set cache key `updated`, assert `handleStreamCache:alreadyUpdated` present at DEBUG and absent at INFO

## 2. Validation

- [x] 2.1 Run `go test ./pkg/lapi/...`
- [x] 2.2 Confirm no product log-level change unless a one-line Debug/Info fix was required
