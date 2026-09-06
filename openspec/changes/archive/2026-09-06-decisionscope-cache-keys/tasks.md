## 1. Ip lookup cache key

- [x] 1.1 Add `IpLookupCacheKey(remoteIP string, ipAddr net.IP) string` in `scope.go`
- [x] 1.2 Wire `LookupCacheKeys` and `LookupCachedRemediation` to use canonical Ip key
- [x] 1.3 Tests: expanded IPv6, IPv4-mapped header, `/128` store pairing

## 2. Range index read safety

- [x] 2.1 `readRangeIndex` returns `(string, error)`; distinguish miss vs unreachable
- [x] 2.2 `ApplyRangeBatch` returns error and skips write on read failure
- [x] 2.3 `client_stream.go` handles apply error (skip write, continue hydrate when possible)
- [x] 2.4 Test: unreachable stub preserves existing index

## 3. Verify

- [x] 3.1 `go test ./pkg/decisionscope/...`
