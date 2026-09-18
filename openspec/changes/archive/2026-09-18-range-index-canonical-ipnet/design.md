## Context

See proposal.md — Why. DestBranch `upsertIndexCIDR` / `removeCIDRFromIndex` compare `existing == cidr` / `network == cidr` after `strings.TrimSpace` only. `AddRange`, `RemoveRange`, and `ApplyRangeBatch` pass that trimmed text. Request membership already `net.ParseCIDR`s each line via `AddCIDR`, so `10.1.2.0/8` still contains `10.1.2.3`. `IPCacheKey` canonicalizes Ip host `/32` `/128` only. Client IP stays `GetRemoteIP`. Stream keys `rangeUpserts` by trimmed LAPI `decision.Value` and still calls `rememberActiveDecision("range:"+cidr)` with that text. CrowdSec overflow Range values are usually `net.IPNet.String()`; the wire can still carry host bits (`knowledge/research/ext_crowdsec_decisions_scopes/notes.md`). `(*net.IPNet).String()` is not lossless for IPv4-mapped CIDRs (explore probe: `::ffff:10.1.2.0/104` → `String()` `10.0.0.0/8`, ones/bits `104/128`).

## Goals / Non-Goals

**Goals:**
- Write-side line identity is `net.ParseCIDR` / `*net.IPNet` (masked IP + prefix ones/bits).
- Equivalent spellings upsert and delete as one network. Persist `(*net.IPNet).String()` for the IPv4 hunt case.
- Incoming unparseable CIDR text is skipped. Unrelated leftover blob spellings stay.

**Non-Goals:**
- Family-preserving persist for IPv4-mapped CIDRs (sibling `2026-09-18-ipv4-mapped-cidr-radix-panic`).
- Bare IP as a Range value (sibling `2026-09-18-range-bare-ip-host-prefix`).
- `rememberActiveDecision("range:"+cidr)` slot keys.
- `IPCacheKey`, live memo keys, `range-index` key name, request-path membership, LAPI `?ip=`.
- Sweep-rewrite of leftover spellings this batch does not touch.

## Decisions

1. **Identity owner is `net.ParseCIDR` / `*net.IPNet`.** Compare with `IP.Equal` and `Mask.Size()` (ones and bits). Persist `(*net.IPNet).String()` on upsert. Alternative: compare `String()` only — rejected; IPv4-mapped `/104` collides with IPv4 `/8`. Alternative: reuse `IPCacheKey` — rejected; that owner is Ip host `/32` `/128`. Do not invent a parallel canonicalizer.

2. **Fix the write helpers and the upsert map they see.** Parse incoming CIDR in `upsertIndexCIDR` / `removeCIDRFromIndex`. Collapse `ApplyRangeBatch` upsert keys onto that same identity (skip empty/unparseable; last write wins per network) so one batch cannot leave two spellings. Removals of equivalent spellings are idempotent. Alternative: canonicalize only in `pkg/lapi` stream — rejected; `AddRange` / `RemoveRange` are the public write path and already fail today.

3. **Unparseable incoming is a no-op.** Do not store verbatim. Do not drop leftover unparseable lines already in the blob. Do not rewrite leftover non-canonical spellings of networks this batch does not upsert or remove. Membership already skips `AddCIDR` errors.

4. **Stream metrics slots stay raw LAPI text.** `ApplyRangeBatch` canonicalizes the blob. `rememberActiveDecision("range:"+cidr)` is out of scope.

5. **Regression lives next to the existing range tests.** `TestHunt_RemoveRangeEquivalentCIDRSpelling` in `pkg/decisionscope/zzz_range_test.go` (or a sibling `zzz_`). Cover hunt delete and equivalent-spelling upsert. Same-spelling tests stay.

## Risks / Trade-offs

- [IPv4-mapped upsert persist] → `String()` can write IPv4 form. Compare still keeps `/8` vs `/104` distinct on this write. Do not add a family-preserving encoder here.
- [Two equivalent keys, different remediations, same batch] → last map write wins after collapse. Same as two sequential `AddRange` calls.
- [Leftover `10.1.2.0/8` until that network is written] → accepted. Next upsert or remove of that network rewrites or drops it. Request membership already parses it.
- [Unparseable leftover lines] → stay in the blob; membership skips them. No sweep.

## Migration Plan

Plugin version bump. No new YAML keys. Existing `range-index` lines keep matching on the request path. The next upsert or remove of a network rewrites or drops every spelling of that network. Rollback is the previous tag (equivalent-spelling delete misses again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
