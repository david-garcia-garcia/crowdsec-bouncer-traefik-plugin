## 1. RemoteAddr gate

- [x] 1.1 In `GetRemoteIP`, extract host from `RemoteAddr` and verify it is in `PoolStrategy.Checker` before calling `getIP`; empty/nil checker or untrusted peer → RemoteAddr only
- [x] 1.2 Keep unparseable-hop fail-closed in `getIP` unchanged

## 2. Unit tests

- [x] 2.1 Update existing header-walk tests to use trusted proxy `RemoteAddr`
- [x] 2.2 Add test: untrusted `RemoteAddr` + forged multi-hop header → `RemoteAddr` host
- [x] 2.3 Add test: empty trusted pool + header present → `RemoteAddr` host
- [x] 2.4 Add tests: malformed hop between trusted and client; malformed rightmost hop; port-suffixed hop

## 3. Docs

- [x] 3.1 Update `knowledge/devdocs/core_plugin_ip.md` GetRemoteIP language for RemoteAddr gate

## 4. Verify

- [x] 4.1 `go test ./pkg/ip/`
