## 1. Close without redial

- [x] 1.1 In `borrow`, if `closed`, return `errUnreachable` without dialing
- [x] 1.2 Change `TestCloseDrainsIdleAndDoesNotRepool` so Get after Close is unreachable and accept count stays 1
- [x] 1.3 Note the local delta on `pkg/simpleredis/SOURCE`

## 2. Communication-layer tests

- [x] 2.1 AUTH once per new dial; not repeated on reuse
- [x] 2.2 SELECT once per new dial when database is set
- [x] 2.3 I/O timeout against a silent accept
- [x] 2.4 Idle-timeout eviction opens a second connection

## 3. Verify

- [x] 3.1 `go test ./pkg/simpleredis ./pkg/cache`
