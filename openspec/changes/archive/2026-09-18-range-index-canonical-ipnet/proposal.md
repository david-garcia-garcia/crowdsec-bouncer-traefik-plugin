## Why

On DestBranch, Range-index upsert and delete identify a line by CIDR text. After `AddRange("10.1.2.0/8")`, `RemoveRange("10.0.0.0/8")` leaves the line, and request membership still bans `10.1.2.3` because it already parses the network. Same-spelling tests pass; equivalent-CIDR delete does not.

## What Changes

- Identify Range-index lines by canonical `net.IPNet` (masked network address plus prefix ones/bits from `net.ParseCIDR`), not by CIDR spelling.
- Upsert replaces every line of that network and persists one `cidr=remediation` whose CIDR is `(*net.IPNet).String()`.
- Remove drops every line of that network. Incoming unparseable CIDR text is skipped.
- Canonicalize `ApplyRangeBatch` upsert keys so one map cannot hold two spellings of the same network.
- Regression: `TestHunt_RemoveRangeEquivalentCIDRSpelling` (delete + matching upsert).
- Spec: write-side identity on `core_plugin_decisions_scopes`. Usage gotcha lands with that contract.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Range-index upsert and remove identify a line by canonical `net.IPNet`, not CIDR text. Lookup keys (`range-index`, client IP, `scope:value`) stay the same. Request-path membership still uses `AddCIDR`.

## Impact

- `pkg/decisionscope/range.go` (`upsertIndexCIDR`, `removeCIDRFromIndex`, incoming `ApplyRangeBatch` keys)
- `pkg/decisionscope/zzz_range_test.go` (or a sibling `zzz_`)
- `openspec/specs/core_plugin_decisions_scopes/spec.md` (delta in this change)
- Usage `knowledge/devdocs/core_plugin_decisionscope.md` after apply (gotcha; not this phase)
- No **BREAKING** public JSON/YAML keys
- Out of scope: `IPCacheKey` / live memo keys, range-index apply-guard, sibling `2026-09-18-range-bare-ip-host-prefix`, `rememberActiveDecision("range:"+cidr)`, `range-index` key name, request-path membership, LAPI `?ip=`
