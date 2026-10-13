# Delivery

## Motivation

When ServeHTTP remediates, TRACE is the breadcrumb operators use to see why. After IP parse, the first line already logs `ip` and `isTrusted`. Mapped CrowdSec scopes for that request — Country, AS, and the rest of `bouncerDecisionScopeHeaders` — are already collected as `RequestScopeValues` immediately before lookup and passed in. The store then merges Ip, present header-scope keys, and Range membership and returns kind, origin, and originID, not which scope fired.

The remediating TRACE still logs `ip`, leftover `cache=hit`, and remediation letter `t` (or `c`). Those mapped values never appear. Live/none miss uses stem `ServeHTTP:LiveLookup` with `ip` and `isBanned` only — same gap. A Country or AS ban looks identical to an Ip ban. `cache=hit` is also the wrong model: the operator-facing story is a store or live lookup, not a cache.

Left alone, TRACE cannot explain which scoped remediations were in play. Operators keep grepping a `cache` attribute that is not the product contract, and they reconstruct headers by hand to tell a header-scope hit from an IP hit.

Priority: P2 — real operator diagnostic pain, with a workaround or limited blast radius

## Implementation

On the remediating path, TRACE reuses the `RequestScopeValues` map already in hand. A helper appends slog group `scopes` (CrowdSec scope name to header value, names sorted) when that map has entries, and omits the group when it is empty. The store-hit `ServeHTTP` line drops `cache` and keeps `ip` plus `remediation`. `ServeHTTP:LiveLookup` keeps `ip` and `isBanned` and gets the same group. The first breadcrumb (`ip`, `isTrusted`) stays. Lookup still returns kind, origin, and originID — no winner field, no Range CIDR. `handleRemediationServeHTTP` stays `ip` and `remediation`. Tests lock present Country and AS, omitted missing headers, no invented keys, and the LiveLookup line.

## What this changes
**Operators.** Remediating TRACE drops `cache=hit` and, when mapped headers are present, adds slog group `scopes` on `ServeHTTP` and `ServeHTTP:LiveLookup`.
**Admin users.** None.
**Developers.** Remediating TRACE must not include `cache`; it must include group `scopes` for present mapped values. The first `ServeHTTP` breadcrumb still requires `ip` and `isTrusted` and must not require `scopes`.
**End users.** None.
