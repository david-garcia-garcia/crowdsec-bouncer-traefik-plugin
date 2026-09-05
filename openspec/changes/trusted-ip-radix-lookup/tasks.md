## 1. In-tree helper

- [ ] 1.1 Add `pkg/iplookup` (`Helper`, `NewHelper`, `NewEmptyHelper`, `AddCIDR`, `IsContained`, `Count`) adapted from traefik-geoblock@0c2f46da with Apache-2.0 header and source cite
- [ ] 1.2 Port geoblock iplookup tests (v4/v6, overlap longest prefix, invalid CIDR, empty helper)

## 2. Checker

- [ ] 2.1 `NewChecker` builds one `Helper`; bare IPv4 `/32`, IPv6 `/128`; drop slice walk in `ContainsIP`
- [ ] 2.2 Checker tests: CIDR hit/miss, bare host, overlapping any-match, empty list, invalid CIDR
- [ ] 2.3 Keep `InNetwork` and Range `MatchRangeFromIndex` unchanged

## 3. Verify

- [ ] 3.1 `go test ./pkg/iplookup/ ./pkg/ip/ ./pkg/bouncer/ ./pkg/configuration/`
