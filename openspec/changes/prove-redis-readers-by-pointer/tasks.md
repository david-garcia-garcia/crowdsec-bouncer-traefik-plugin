## 1. Construction-site test

- [ ] 1.1 Add `Test_NewKeepsRedisReadersByPointer` in `pkg/cache/cache_test.go`: `Client.New` with two read hosts; distinct non-nil writer/reader pointers; `nextReader` returns those same pointers via `indexOfReader`
- [ ] 1.2 Close the client at the end of the test

## 2. Verify

- [ ] 2.1 `go test ./pkg/cache/ -count=1`
- [ ] 2.2 `go vet ./pkg/cache/`
