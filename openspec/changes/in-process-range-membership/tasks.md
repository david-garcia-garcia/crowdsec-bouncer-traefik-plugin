## 1. Membership type

- [ ] 1.1 Add `RangeMembership` in `pkg/decisionscope` (ban Helper, captcha Helper, `MembershipFromIndex`, `Remediation` ban-then-captcha)
- [ ] 1.2 Tests: ban wins over overlapping captcha, miss, empty blob, invalid CIDR line skipped, IPv4/IPv6 families

## 2. Request path

- [ ] 2.1 `LookupCachedRemediation` takes membership; `LookupCacheKeys` omits `RangeIndexKey` in stream/alone
- [ ] 2.2 `bouncer.ServeHTTP` passes the connection’s current membership
- [ ] 2.3 Existing decisionscope tests still pass (header scopes, none skips Range, ban across scopes)

## 3. Connection hydrate

- [ ] 3.1 `CrowdsecConnection` holds `atomic.Pointer` of membership; `Close` drops it with the connection
- [ ] 3.2 `startStream` GETs `range-index` and stores membership before returning
- [ ] 3.3 `handleStreamCache` lease miss: `ApplyRangeBatch` then rebuild from the written blob
- [ ] 3.4 `handleStreamCache` lease hit: GET blob, rebuild if the raw string changed; GET error keeps last membership
- [ ] 3.5 Tests: replica hydrate without stream New/Deleted; empty blob; Redis GET failure does not wipe membership

## 4. Docs

- [ ] 4.1 Update `knowledge/devdocs/core_plugin_decisionscope.md` Language Avoid and lookup snippet
- [ ] 4.2 Update `knowledge/devdocs/core_plugin_ip.md` (Range may reuse Helper; still not Checker)

## 5. Verify

- [ ] 5.1 `go test ./pkg/decisionscope/ ./pkg/crowdsecconnection/ ./pkg/bouncer/ ./pkg/iplookup/`
