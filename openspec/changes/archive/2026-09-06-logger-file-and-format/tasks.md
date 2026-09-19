## 1. Logger implementation

- [x] 1.1 Add process-lifetime shared file map in `pkg/logger/logger.go`
- [x] 1.2 Use `strings.EqualFold` for JSON format selection
- [x] 1.3 Add unit test: `NewWithFormat` with `"JSON"` emits valid JSON
- [x] 1.4 Add unit test: two `NewWithFormat` calls with same temp path share one file

## 2. Validation

- [x] 2.1 Run `go test ./pkg/logger/...`
- [x] 2.2 Run full repo test suite if CI expects it
