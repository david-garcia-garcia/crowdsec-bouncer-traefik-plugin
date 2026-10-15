## 1. Drop importer

- [x] 1.1 Delete `BenchmarkHeapRetained_TTLMap100k` and the `ttl_map "github.com/leprosus/golang-ttl-map"` import from `pkg/decisionstore/zzz_lookup_bench_test.go`. Keep `BenchmarkHeapRetained_LiveMap100k` and the rest of that file. Do not edit `pkg/decisionstore/memory.go`.

## 2. Drop module graph

- [x] 2.1 Run `go mod tidy` then `go mod vendor`. Confirm `go.mod` no longer requires `github.com/leprosus/golang-ttl-map`, the two `go.sum` lines are gone, `vendor/modules.txt` no longer lists that module, and `vendor/github.com/leprosus/golang-ttl-map/` is gone. Do not invent extra leftovers.

## 3. Drop lint allow

- [x] 3.1 Remove the Test depguard `allow` entry for `github.com/leprosus/golang-ttl-map` from `.golangci.yml`. Do not change the Main allow list.
