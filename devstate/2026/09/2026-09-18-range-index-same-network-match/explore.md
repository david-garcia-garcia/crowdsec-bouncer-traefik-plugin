# Explore
IssueKey: 2026-09-18-range-index-same-network-match

## Concepts

```
  incoming CIDR text ──persist──► range-index line "cidr=remediation"
                                         │
                    upsert / remove today│ string ==
                    desired              │ same network (masked IP + prefix)
                                         ▼
                         MembershipFromIndex ParseCIDR → trees
                         10.1.2.3 ∈ 10.1.2.0/8  (network 10.0.0.0/8)
```

- **Line identity** (this ticket) is only how `upsertIndexCIDR` and `removeCIDRFromIndex` decide two CIDR strings are the same blob line. Membership already parses; hydrate already rebuilds from whatever lines remain.
- **Persist** stays the incoming trimmed text. Replacing a matched line writes that incoming spelling plus the new remediation. That is not a sweep-rewrite and not `(*net.IPNet).String()`.
- **`net.ParseCIDR` returns two addresses.** Measured on this tree: `10.1.2.0/8` → first IP `10.1.2.0`, `IPNet` `10.0.0.0/8`, mask `8/32`. `10.0.0.0/8` → first IP `10.0.0.0`, same `IPNet` and mask. First-IP `Equal` is false; masked-IP `Equal` plus `Mask.Size()` is true. Compare the `*IPNet`, not the first return.
- **`ApplyRangeBatch` on this DestBranch** already removes then upserts, one read, one write; a non-miss GET error returns and does not write. Keep that shape. Requirement "Current" wording that lists upsert-then-remove is stale versus `pkg/decisionscope/range.go`.
- **Closed PR #92** is a different apply (canonical persist, collapse, identity helpers) and is out of scope. Do not copy it.

## Decisions

- Bound the apply to `upsertIndexCIDR` and `removeCIDRFromIndex` plus one small unexported helper next to those loops. Do not change `ApplyRangeBatch` order or read-error contract, hydrate, `MembershipFromIndex`, metrics keys, bare-IP host-prefix, or IPv4-mapped persist.
- Compare with `net.ParseCIDR` on both sides, then `IPNet.IP.Equal` and the same `Mask.Size()` ones and bits. Do not compare `ParseCIDR`'s first `IP` (host bits). Do not use `Mask.String()`. Do not introduce `indexNetworkID`, `collapseRangeUpserts`, `hasParseableIndexCIDR`, or dual identity helpers.
- When either side fails `ParseCIDR`, keep today's raw-text `==` so identical unparseable lines still match.
- A same-network hit replaces or drops **every** matching line (today's `==` already walks the whole blob). Do not collapse leftover duplicate spellings into one line.
- Persist the incoming CIDR text on replace/append. Do not rewrite other leftover spellings this poll did not name.
- Spec host is existing `core_plugin_decisions_scopes` (Range index line identity). Usage packet `core_plugin_decisionscope.md` already names Range index; do not rename that pair. Add a same-network scenario on propose; add the usage gotcha when the apply makes it true (devdocsimpact if propose skips).
- Client address and Traefik process lifetime are not this ticket. `GetRemoteIP` stays the client-IP owner. No reclaim work.
- No third-party research write: compare form is Go `net.ParseCIDR` plus a product choice; IPv4-mapped CIDR facts already live in `knowledge/research/std_go_net_ipv4-mapped-cidr/` and stay out of scope.
- Test the required pair in `pkg/decisionscope/zzz_range_test.go`. Keep `pkg/lapi/zzz_ipcachekey_test.go` unread-base tests passing.

## Open questions

- Q: Which ticket-allowed compare form does this run use (`IP.Equal` + mask ones/bits vs `Mask.String()`)?
  Decision: resolved — `*net.IPNet.IP.Equal` plus matching `Mask.Size()` ones and bits. Do not compare `ParseCIDR`'s first IP (`10.1.2.0` ≠ `10.0.0.0` on the required pair). Do not use `Mask.String()`.
  By: explore

- Q: What happens when either side fails `ParseCIDR`?
  Decision: resolved — fall back to raw-text `==` (today's identical-garbage match). If one side parses and the other does not, they are not the same line unless the strings are equal (they will not be).
  By: explore

- Q: What is the helper named and where does it live?
  Decision: resolved — one unexported `indexCIDRsSameNetwork(existing, cidr string) bool` in `pkg/decisionscope/range.go` next to the two loops. Not `indexNetworkID`.
  By: propose

- Q: Which spec leaf takes the same-network requirement?
  Decision: resolved — fold onto `core_plugin_decisions_scopes`. Do not open a new family and do not rename `core_plugin_decisionscope` / `core_plugin_decisions_scopes`.
  By: explore

- Q: If the blob already has two leftover spellings of the same network, does upsert replace both?
  Decision: resolved — yes, every same-network line; each replaced line is rewritten to the incoming text plus the new remediation. Do not add `collapseRangeUpserts` if that leaves two identical new lines.
  By: explore

- Q: Which extra tests beyond `AddRange(10.1.2.0/8)` then `RemoveRange(10.0.0.0/8)`?
  Decision: resolved — one unparseable identical-text remove next to the required case to lock the fallback. No IPv4-mapped, collapse, persist-rewrite, or hydrate tests. Unread-base apply tests stay as they are.
  By: propose

- Q: Does explore write the usage gotcha now?
  Decision: resolved — no during explore; implement writes the Gotchas bullet now that the tree keeps the contract.
  By: implement

- Q: Does the helper remap IPv4-mapped CIDRs so `10.0.0.0/8` matches `::ffff:10.0.0.0/104`?
  Decision: resolved — no. Out of scope. `IP.Equal` may treat mapped and v4 addresses as equal, but `Mask.Size()` ones/bits differ; leave that as a miss.
  By: explore
