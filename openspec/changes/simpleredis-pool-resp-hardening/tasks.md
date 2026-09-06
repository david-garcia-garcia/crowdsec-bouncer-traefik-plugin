## 1. Pool and close hardening

- [x] 1.1 Add `maxOpenConns`, `open` counter, RESP cap constants to `simpleredis.go`
- [x] 1.2 Serialize close vs dial in `borrow()`; reserve slot before dial; re-check `closed` after dial
- [x] 1.3 Track `open` in `release()` and `Close()`

## 2. RESP and error handling

- [x] 2.1 Cap bulk length and array count before allocation in `readBulk`/`readReply`
- [x] 2.2 Return non-reusable from `do()` on session-fatal `-ERR` replies

## 3. Tests

- [x] 3.1 Concurrent Close-during-dial test
- [x] 3.2 Peak connection cap test (>8 goroutines)
- [x] 3.3 Oversized bulk/array fake-server tests
- [x] 3.4 NOAUTH on reused conn does not repool
- [x] 3.5 Dial AUTH/SELECT failure, Set/Del/MGet after Close, Get unexpected reply

## 4. Verify

- [x] 4.1 `go test ./pkg/simpleredis/ -count=1`
- [x] 4.2 `go vet ./pkg/simpleredis/`
