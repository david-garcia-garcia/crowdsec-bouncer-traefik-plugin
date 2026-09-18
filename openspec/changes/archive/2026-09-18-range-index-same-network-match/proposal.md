## Why

Range-index upsert and delete identify a blob line by raw CIDR text. `AddRange(10.1.2.0/8)` stores that spelling, membership parses it so `10.1.2.3` is banned, and `RemoveRange(10.0.0.0/8)` leaves the line because the strings differ. Hydrate rebuilds from the leftover, so the ban stays.

## What Changes

- In `upsertIndexCIDR` and `removeCIDRFromIndex` only, treat two CIDR strings as the same line when both parse and the `*net.IPNet` masked IP and prefix match.
- Persist the incoming trimmed CIDR text as today. Do not rewrite leftover spellings this call did not name, and do not persist `(*net.IPNet).String()`.
- Keep master's `ApplyRangeBatch` shape and read-error contract (failed GET, not miss, returns and MUST NOT write).
- One unexported same-network helper next to those two loops.
- Test: `AddRange(10.1.2.0/8)` then `RemoveRange(10.0.0.0/8)` clears membership for `10.1.2.3`. Keep existing unread-base apply tests passing.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_decisions_scopes`: Range-index upsert and remove match a line by same network (masked IP + prefix), not raw CIDR text.

## Impact

- `pkg/decisionscope/range.go` (`upsertIndexCIDR`, `removeCIDRFromIndex`, one helper next to those loops)
- `pkg/decisionscope/zzz_range_test.go` (equivalent-network remove after add; one unparseable identical-text fallback)
- Existing unread-base apply tests stay: `pkg/lapi/zzz_ipcachekey_test.go`
- No **BREAKING** public JSON/YAML keys
- Out of scope: `indexNetworkID`, `collapseRangeUpserts`, `hasParseableIndexCIDR` early-return, dual identity helpers, persist rewrite, sweep-rewrite of leftover spellings, metrics slot keys, bare-IP host-prefix, IPv4-mapped persist, hydrate / `MembershipFromIndex` / `ApplyRangeBatch` read-error shape, closed PR #92 / branch `2026-09-18-range-index-cidr-canonical-delete`
