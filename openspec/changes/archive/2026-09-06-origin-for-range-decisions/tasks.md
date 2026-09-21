## 1. Stream upsert

- [x] 1.1 Store Range stream upserts as `RemediationWithOrigin(letter, MetricsOrigin(origin, scenario))` in `connection_stream.go`
- [x] 1.2 Leave `rememberActiveDecision` unchanged

## 2. Membership suffix

- [x] 2.1 `MembershipFromIndex` keeps cidr→stored; `Remediation` returns the winning CIDR’s stored string (ban over captcha; longest-prefix among that kind)
- [x] 2.2 Bare `cidr=t` still returns `t`. Suffixed line returns letter plus origin
- [x] 2.3 Tests: two overlapping bans pick one stored suffix; letter-only still bans

## 3. Lookup and blob

- [x] 3.1 Blob round-trip: `ApplyRangeBatch` / `parseIndexLine` keep a suffix with no `=`
- [x] 3.2 `LookupCachedRemediation` Range-only origin matches Ip/header; update the empty-origin comment
- [x] 3.3 Tests: Range-only lookup origin; old letter-only line still bans

## 4. Docs

- [x] 4.1 Usage packets: drop “range-index stays letter-only”; blob MAY carry suffix; Range-only origin
- [x] 4.2 Spec deltas already in this change (`core_plugin_lapi_usage-metrics`, `core_plugin_decisions_scopes`)

## 5. Verify

- [x] 5.1 `go test ./pkg/decisionscope/ ./pkg/crowdsecconnection/ ./pkg/cache/`
