## 1. Radix endpoint payload

- [ ] 1.1 Store the remediation string on `radixNode` and set it from insert when provided
- [ ] 1.2 Add `AddCIDRRemediation` (boolean `AddCIDR` stays empty payload) and `ContainedRemediation` (`IsContained` stays boolean)
- [ ] 1.3 Keep IPv4-mapped remap; last insert of that kind wins on the same remapped endpoint

## 2. Range membership

- [ ] 2.1 Hydrate with `AddCIDRRemediation`; drop `storedByCIDR` and `storedMatchingPrefix`
- [ ] 2.2 `Remediation` asks ban then captcha `ContainedRemediation`; nil/empty membership stays a miss

## 3. Tests and usage

- [ ] 3.1 Keep existing `zzz_range*_test.go` / `zzz_iplookup_test.go` locks; add longest-prefix origin-on-node and remapped last-insert
- [ ] 3.2 Update `knowledge/devdocs/core_plugin_decisionscope.md` and `core_plugin_ip.md` so a Range helper endpoint MAY carry the stored string; Checker stays boolean
