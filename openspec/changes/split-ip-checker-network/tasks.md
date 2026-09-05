## 1. Split files

- [ ] 1.1 Move Checker, PoolStrategy, GetRemoteIP, parseIP, and the package comment into `pkg/ip/checker.go`; fix the GetRemoteIP comment to name the RemoteAddr fallback
- [ ] 1.2 Move InNetwork into `pkg/ip/network.go`; delete `pkg/ip/ip.go`

## 2. Tests

- [ ] 2.1 Move `TestCheckerContains` and `TestCheckerContainsCatchAllFamily` to `pkg/ip/checker_test.go`
- [ ] 2.2 Add GetRemoteIP tests in `checker_test.go`: no header → RemoteAddr host; XFF right-to-left skip trusted hops; all hops trusted → RemoteAddr; empty segments skipped; custom header name; RemoteAddr without port → error
- [ ] 2.3 Move `TestInNetwork` to `pkg/ip/network_test.go`; delete `pkg/ip/ip_test.go`

## 3. Usage

- [ ] 3.1 Update `knowledge/devdocs/core_plugin_ip.md` Key files to `checker.go` / `network.go`

## 4. Verify

- [ ] 4.1 `go test ./pkg/ip/ ./pkg/bouncer/`
