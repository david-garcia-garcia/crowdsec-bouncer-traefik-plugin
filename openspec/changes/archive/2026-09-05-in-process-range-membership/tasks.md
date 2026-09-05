## 1. Membership type

- [x] 1.1 Add `RangeMembership` in `pkg/decisionscope` (ban Helper, captcha Helper, `MembershipFromIndex`, `Remediation` ban-then-captcha)
- [x] 1.2 Tests: ban wins over overlapping captcha, miss, empty blob, invalid CIDR line skipped, IPv4/IPv6 families

## 2. Request path

- [x] 2.1 `LookupCachedRemediation` takes membership; `LookupCacheKeys` omits `RangeIndexKey` in stream/alone
- [x] 2.2 `bouncer.ServeHTTP` passes the connection’s current membership
- [x] 2.3 Existing decisionscope tests still pass (header scopes, none skips Range, ban across scopes)

## 3. Connection hydrate

- [x] 3.1 `CrowdsecConnection` holds `atomic.Value` of membership; `Close` drops it with the connection
- [x] 3.2 `startStream` GETs `range-index` and stores membership before returning
- [x] 3.3 `handleStreamCache` lease miss: `ApplyRangeBatch` then rebuild from the written blob
- [x] 3.4 `handleStreamCache` lease hit: GET blob, rebuild if the raw string changed; GET error keeps last membership
- [x] 3.5 Tests: replica hydrate without stream New/Deleted; empty blob; Redis GET failure does not wipe membership

## 4. Docs

- [x] 4.1 Update `knowledge/devdocs/core_plugin_decisionscope.md` Language Avoid and lookup snippet
- [x] 4.2 Update `knowledge/devdocs/core_plugin_ip.md` (Range may reuse Helper; still not Checker)

## 5. Verify

- [x] 5.1 `go test ./pkg/decisionscope/ ./pkg/crowdsecconnection/ ./pkg/bouncer/ ./pkg/iplookup/`
