## 1. Stream tick log tests

- [ ] 1.1 Add `pkg/lapi/client_stream_log_test.go` with slog JSON buffer helpers at INFO and DEBUG
- [ ] 1.2 Lease-miss: mock LAPI stream fetch, assert `handleStreamCache:updated` present at DEBUG and absent at INFO
- [ ] 1.3 Lease-hit: set cache key `updated`, assert `handleStreamCache:alreadyUpdated` present at DEBUG and absent at INFO

## 2. Validation

- [ ] 2.1 Run `go test ./pkg/lapi/...`
- [ ] 2.2 Confirm no product log-level change unless a one-line Debug/Info fix was required
