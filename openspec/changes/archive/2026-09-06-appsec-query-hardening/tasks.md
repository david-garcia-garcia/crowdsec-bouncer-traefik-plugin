## 1. Query hardening

- [x] 1.1 Drain response on all non-nil `Do` results before failure-action return (502/503/504)
- [x] 1.2 Filter hop-by-hop and body metadata headers; set `Content-Length` from forwarded bytes
- [x] 1.3 Route `readCappedAppsecBody` errors through `resultForFailureAction`
- [x] 1.4 Forward full POST body when `appsecBodyLimit == 0`

## 2. Tests

- [x] 2.1 Connection reuse tests for 502, 503, 504
- [x] 2.2 Outbound header/body-length assertion after truncation
- [x] 2.3 Failure-action on response read error
- [x] 2.4 Body limit zero forwards POST body

## 3. Verify

- [x] 3.1 `go test ./pkg/appsec/...`
- [x] 3.2 Mark tasks complete
