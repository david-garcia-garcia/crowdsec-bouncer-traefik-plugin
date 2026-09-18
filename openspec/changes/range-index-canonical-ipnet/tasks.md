## 1. Write-side identity

- [ ] 1.1 Parse incoming CIDR with `net.ParseCIDR` in `upsertIndexCIDR` / `removeCIDRFromIndex`. Compare existing lines by masked IP plus prefix ones/bits. Skip incoming unparseable. Keep leftover unparseable lines
- [ ] 1.2 Persist `(*net.IPNet).String()` on upsert. Replace or drop every line of that network. Do not rewrite unrelated leftover spellings

## 2. Batch keys

- [ ] 2.1 Collapse `ApplyRangeBatch` upsert keys onto the same identity (skip empty/unparseable; last write wins per network) so one map cannot hold two spellings

## 3. Tests

- [ ] 3.1 Add `TestHunt_RemoveRangeEquivalentCIDRSpelling` in `pkg/decisionscope/zzz_range_test.go` (or a sibling `zzz_`): `AddRange("10.1.2.0/8")` then `RemoveRange("10.0.0.0/8")` leaves `10.1.2.3` unbanned
- [ ] 3.2 Cover equivalent-spelling upsert (captcha then ban) and keep existing same-spelling tests

## 4. Docs

- [ ] 4.1 Usage gotcha on `knowledge/devdocs/core_plugin_decisionscope.md`: write identity is the canonical network
- [ ] 4.2 Spec delta already in this change (`core_plugin_decisions_scopes`)

## 5. Verify

- [ ] 5.1 `go test ./pkg/decisionscope/`
