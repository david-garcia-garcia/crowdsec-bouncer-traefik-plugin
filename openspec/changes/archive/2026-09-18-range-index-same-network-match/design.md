## Context

See `proposal.md` Why. Dest `upsertIndexCIDR` / `removeCIDRFromIndex` compare `existing == cidr` / `network == cidr` (`pkg/decisionscope/range.go`). Membership already `ParseCIDR`s leftover lines, so `10.1.2.3` stays banned after `RemoveRange(10.0.0.0/8)`. `ApplyRangeBatch` already removes then upserts, one read, one write; a non-miss GET error returns and does not write. Persist is the incoming trimmed text.

FindSpecHost:

```
verdicts:
  - { deltaId: range-index-same-network-match, fold|new: fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_lapi_stream-apply] }
```

Search: `core_plugin_decisions_scopes` already owns the Range-index blob, apply read-error, membership, and hydrate. Same-network line identity is a one-requirement bugfix of that leaf. `core_plugin_lapi_stream-apply` owns deleted-before-new order, not CIDR string identity. No in-flight change folder. Closed PR #92 / `2026-09-18-range-index-cidr-canonical-delete` is a different apply (canonical persist, collapse, identity helpers) and is out of scope.

## Goals / Non-Goals

**Goals:**

- Same-network compare only in the two index loops (plus one unexported helper next to them).
- Incoming CIDR text stays the persisted spelling.
- Required add-then-remove pair and the unparseable identical-text fallback.

**Non-Goals:**

- `indexNetworkID`, `collapseRangeUpserts`, `hasParseableIndexCIDR`, dual identity helpers.
- Changing `ApplyRangeBatch` order or read-error contract, hydrate, or `MembershipFromIndex`.
- Persist rewrite, leftover sweep, metrics keys, bare-IP host-prefix, IPv4-mapped persist.
- Reusing closed PR #92.

## Decisions

1. **One helper `indexCIDRsSameNetwork(existing, cidr string) bool` in `pkg/decisionscope/range.go` next to the two loops.** Both loops call it in place of `==`. Alternative: inline the parse in each loop — rejected (two copies of the same fact). Not `indexNetworkID` (that would be a second identity owner).
2. **Compare the `*net.IPNet`, not `ParseCIDR`'s first IP.** `10.1.2.0/8` and `10.0.0.0/8` share masked IP `10.0.0.0` and `Mask.Size()` `8/32`; first-IP `Equal` is false. Use `IPNet.IP.Equal` plus matching ones and bits. Alternative: `Mask.String()` — rejected (explore closed it). Alternative: persist `(*net.IPNet).String()` — rejected (ticket forbids rewrite).
3. **Parse failure falls back to raw-text `==`.** One side parseable and the other not is a miss unless the strings are equal. Alternative: `hasParseableIndexCIDR` early-return — rejected (out of scope; would change unparseable identical-text match).
4. **Walk every same-network line.** Today's `==` already walks the blob. Do not collapse leftover duplicate spellings into one line. Each replaced line is rewritten to the incoming text plus the new remediation.
5. **Tests in `pkg/decisionscope/zzz_range_test.go`.** Required pair plus one unparseable identical-text remove. Keep `pkg/lapi/zzz_ipcachekey_test.go` unread-base tests as they are. No IPv4-mapped, collapse, persist-rewrite, or hydrate tests.
6. **Fold onto `core_plugin_decisions_scopes`.** Do not open a new family. Usage gotcha waits for apply / `sbs-dev-devdocsimpact` so the packet does not claim a contract the tree does not yet keep.

## Risks / Trade-offs

- [Two leftover spellings of one network become two identical incoming lines after upsert] → accepted; collapse is out of scope. Remove still drops every same-network line.
- [IPv4-mapped `::ffff:10.0.0.0/104` does not match `10.0.0.0/8`] → accepted miss; mapped persist is out of scope. `Mask.Size()` ones/bits differ.

## Migration Plan

No operator JSON/YAML key change. Existing blobs keep their spellings. Rollback is revert.

## Open Questions

None — ticket decisions stand on `explore.md`.
