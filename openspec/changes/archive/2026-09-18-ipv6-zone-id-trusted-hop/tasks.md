## 1. parseIP

- [x] 1.1 In `parseIP`, cut the last `%` when the prefix contains `:`, then call existing `net.ParseIP`. Do not import `netip`. Do not strip brackets. Do not change `GetRemoteIP` or `Contains` besides this shared parse.
- [x] 1.2 Leave `NewChecker` pool entries and `Family` / `FamilyOfHostOrCIDR` on `net.ParseIP`.

## 2. Tests

- [x] 2.1 `TestCheckerContains`: `Contains("fe80::1%eth0")` against pool `fe80::/10` is true.
- [x] 2.2 `TestGetRemoteIP`: `RemoteAddr` `[fe80::1%eth0]:443`, pool `fe80::/10`, `X-Forwarded-For: 203.0.113.10` returns `203.0.113.10` with a parsed `net.IP`.
- [x] 2.3 Same table: missing header returns `fe80::1%eth0` with a parsed `net.IP`; hop `fe80::1%eth0` keeps that text and a parsed `net.IP`; hop `[fe80::1%eth0]` stays fail-closed.
- [x] 2.4 Do not add or depend on `TestHunt_ZonedIPv6RemoteAddrIsTrustedHop`.

## 3. Verify

- [x] 3.1 `go test ./pkg/ip -count=1` and existing `TestGetRemoteIP` / `TestCheckerContains` still pass.
