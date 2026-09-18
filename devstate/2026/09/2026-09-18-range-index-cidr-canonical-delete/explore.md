# Explore

## Concepts

```
  LAPI / AddRange text          Range-index blob              Request path
  ─────────────────             ────────────────              ────────────
  "10.1.2.0/8"  ──trim──►  upsertIndexCIDR                    MembershipFromIndex
                              existing == cidr  (string)         │
                              write cidr=remediation             ▼
                                                                 AddCIDR → net.ParseCIDR
  RemoveRange("10.0.0.0/8")                                      10.1.2.0/8 → net 10.0.0.0/8
       │                                                         Contains(10.1.2.3) = true
       ▼
  removeCIDRFromIndex
  network == cidr  (string)  → miss → leftover line still bans
```

- **Range-index line identity (write)** today is trimmed CIDR text. `upsertIndexCIDR` replaces only when `existing == cidr`. `removeCIDRFromIndex` drops only when `network == cidr`. `AddRange` / `RemoveRange` / `ApplyRangeBatch` pass `strings.TrimSpace` only. `pkg/decisionscope/range.go`
- **Range membership (read)** already uses the network. `MembershipFromIndex` feeds each line to `iplookup.Helper.AddCIDR`, which `net.ParseCIDR`s and inserts the masked block. Invalid CIDR lines are skipped. `pkg/decisionscope/rangemembership.go` `pkg/iplookup/iplookup.go`
- **The defect** is that split: after `AddRange("10.1.2.0/8")`, `RemoveRange("10.0.0.0/8")` does not drop the line, but `10.1.2.3` still matches. Same-spelling tests pass (`TestRemoveRange`, `TestAddRangeUpdatesRemediation`). `TestHunt_RemoveRangeEquivalentCIDRSpelling` is not in this tree.
- **Desired identity** is canonical `net.IPNet`: masked network address plus prefix length. Persist that network; compare existing lines by the same fact, not by the blob’s CIDR spelling.
- **Owner of that fact** is Go `net.ParseCIDR` / `*net.IPNet` (IP already masked + `Mask.Size()`). Not `IPCacheKey` (Ip host `/32` `/128` only). Not `pkg/ip` (membership/family). Not `iplookup` (containment tree). Client address stays `GetRemoteIP`; this change does not reconstruct it.
- **Stream apply** already batches Range through `ApplyRangeBatch`. LAPI `decision.Value` is only trimmed; `rangeUpserts` is keyed by that text. `pkg/lapi/client_stream.go`. CrowdSec overflow Range values are usually `net.IPNet.String()`; the wire can still carry host bits, and this plugin can write them. `knowledge/research/ext_crowdsec_decisions_scopes/notes.md`
- **Cache key `range-index` does not change.** Spec “Lookup keys MUST NOT change” names `range-index`, client IP, and `scope:value`, not CIDR text inside the blob. `storedByCIDR` keys by the blob spelling and re-parses on lookup; a canonical write changes that map key after the next hydrate, not request-path containment.
- **`(*net.IPNet).String()` is not lossless for IPv4-mapped CIDRs.** Probe: `ParseCIDR("10.1.2.0/8")` → net `10.0.0.0/8` (8/32); `ParseCIDR("::ffff:10.1.2.0/104")` → `String()` `10.0.0.0/8` but ones/bits `104/128`. Identity compare must use network IP + prefix (ones, bits), not `String()` alone.

## Decisions

- Fix write-side identity in `upsertIndexCIDR` / `removeCIDRFromIndex` (and the incoming keys those helpers see). Bound: do not change `range-index` key name, request-path membership, LAPI `?ip=`, `IPCacheKey`, or live memo keys.
- Parse both the incoming CIDR and each existing line. Upsert replaces every line of that network with one `cidr=remediation` whose CIDR is `(*net.IPNet).String()`. Remove drops every line of that network.
- Canonicalize incoming `ApplyRangeBatch` upsert keys (and skip empty/unparseable) so one map cannot hold two spellings of the same network under random iteration. Removals of equivalent spellings are idempotent.
- Regression: `TestHunt_RemoveRangeEquivalentCIDRSpelling` in `pkg/decisionscope/zzz_range_test.go` (or a sibling `zzz_`). Cover the hunt delete and the matching upsert (equivalent spelling replaces remediation).
- Propose folds a write-side identity requirement onto `openspec/specs/core_plugin_decisions_scopes`. Usage gotcha on `knowledge/devdocs/core_plugin_decisionscope.md` lands with that contract (not written this phase).
- No new research folder. Existing CrowdSec Range encoding packet plus the ParseCIDR probe answer the outside facts.
- No Language write this phase. Terms Range index / Range membership already match the tree.

## Open questions

- Q: Who already owns Range-index line identity (the network a blob line is)?
  Decision: resolved — Go `net.ParseCIDR` / `*net.IPNet` (masked network IP + prefix ones/bits). Reuse that output. Do not invent a parallel canonicalizer. Do not reuse `IPCacheKey`. Client address, user, tenant, Host, and trust hop are not reconstructed here (`GetRemoteIP` already owns the client IP).
  By: explore

- Q: Is unparseable CIDR text stored verbatim or dropped?
  Decision: assumed — drop incoming unparseable upserts and removals (empty after trim already no-ops). Membership already skips `AddCIDR` errors. Do not sweep leftover unparseable lines already in the blob.
  By: explore

- Q: Does a later batch rewrite leftover non-canonical spellings already in the blob, or only the network being upserted/removed?
  Decision: assumed — parse existing lines so a leftover `10.1.2.0/8` is the same network as `10.0.0.0/8`. Rewrite or drop only lines of a network this batch upserts or removes. Do not sweep-rewrite unrelated leftover spellings.
  By: explore

- Q: Are an IPv4 CIDR and an IPv4-mapped IPv6 CIDR whose `String()` collides the same Range-index line?
  Decision: assumed — no. Compare by network IP + prefix (ones, bits). Persist `(*net.IPNet).String()` for the IPv4 hunt case. Do not add a family-preserving encoder or take sibling `2026-09-18-ipv4-mapped-cidr-radix-panic`.
  By: explore

- Q: Does this change also canonicalize `rememberActiveDecision("range:"+cidr)` slots that still use raw LAPI text?
  Decision: assumed — no. Metrics slot keys stay out of scope. Range-index blob identity is the defect.
  By: explore

- Q: Bare IP as a Range value (`10.1.2.3` without a prefix)?
  Decision: assumed — `ParseCIDR` fails; drop (same as other unparseable). Do not take sibling `2026-09-18-range-bare-ip-host-prefix`.
  By: explore
