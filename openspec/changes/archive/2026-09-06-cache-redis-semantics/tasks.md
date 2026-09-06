## 1. Cache API

- [x] 1.1 `duration <= 0` no-op on memory and Redis; document on `Client.Set`
- [x] 1.2 `Set`/`Delete` return `error`; Redis propagates write failures
- [x] 1.3 Read-your-writes: track successful Sets; route Get/GetMany to writer for tracked keys

## 2. Call sites

- [x] 2.1 Update `pkg/lapi`, `pkg/decisionscope`, `pkg/captcha` and tests to compile with new signature

## 3. Tests

- [x] 3.1 Redis CRUD parity: Set/Get/Delete, TTL zero, write errors, prefix, empty value miss, GetMany
- [x] 3.2 Read-your-writes test with lagging replica fake

## 4. Verify

- [x] 4.1 `go test ./pkg/cache/ ./pkg/lapi/ ./pkg/decisionscope/`
