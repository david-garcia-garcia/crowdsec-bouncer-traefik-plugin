# Explore
IssueKey: 2026-09-06-origin-for-range-decisions

## Concepts

**Range-index blob**: one cache string at key `range-index`, lines `cidr=remediation`. Redis replicas share it. `parseIndexLine` splits on the first `=`. The remediation side may already be `t`/`c` or `t`/`c` plus U+001F plus origin; upsert already writes that suffix unchanged.

**Range membership**: two boolean `iplookup.Helper`s (ban, captcha) rebuilt from the blob. Helper has no payload (`IsContained` → found + prefixLen). Request lookup asks this pair, not Redis.

**Winning CIDR suffix**: the stored remediation string of the CIDR that wins (ban over captcha). Lookup already splits that string with `RemediationKind` / `RemediationOrigin`. Ip/header already store `RemediationWithOrigin`. Range does not.

**Metrics origin**: `MetricsOrigin(decision.Origin, decision.Scenario)` at stream apply. Gauge already records it via `rememberActiveDecision`. Dropped items take origin from `LookupCachedRemediation`. Empty origin is omitted on POST (`IncDropped`).

```
stream New[Range]
        │
        ▼
rangeUpserts[cidr] = letter          ← today
rangeUpserts[cidr] = letter+US+origin ← desired
        │
        ▼
ApplyRangeBatch → one range-index blob
        │
        ▼
MembershipFromIndex → Helpers + cidr→stored
        │
        ▼
Remediation(ip) → winning stored string
        │
        ▼
LookupCachedRemediation → kind, origin
        │
        ▼
IncDropped(origin, ip_type, ban|captcha)
```

## Decisions

- Reuse `cache.RemediationWithOrigin` and `MetricsOrigin` at Range upsert. Do not invent a second codec.
- Keep one `range-index` key. Do not add per-CIDR or per-host keys. Do not change `rememberActiveDecision`.
- Keep Helper boolean. On a Range hit, resolve origin from a cidr→stored map built in `MembershipFromIndex`. Miss path stays two tree lookups.
- `LookupCachedRemediation` already keeps a ban’s suffix (`PreferRemediation`) and returns `RemediationOrigin`. Change membership output; update the Range-only-empty comment.
- Bare `cidr=t` still matches (`IsActiveRemediation` / `RemediationKind` already ignore a missing suffix).
- Fold into existing specs `core_plugin_lapi_usage-metrics` and `core_plugin_decisions_scopes`. Update usage packets that say letter-only. No new research folder: `ext_crowdsec_lapi_usage-metrics` already owns origin labels.
- Client IP stays `pkg/ip.GetRemoteIP`. Origin stays LAPI `Origin`/`Scenario` via `MetricsOrigin` at apply time. Do not re-parse RemoteAddr or reconstruct origin at lookup.

## Open questions

- Q: Who already owns client identity and metrics origin for this path?
  Decision: resolved — client IP is `pkg/ip.GetRemoteIP` (bouncer already passes it). Origin is `MetricsOrigin(decision.Origin, decision.Scenario)` at stream apply. Lookup must not re-derive either.
  By: explore

- Q: Which ban CIDR’s origin is returned when several containing bans hit, given Helper has no payload?
  Decision: assumed — pick the longest-prefix matching ban CIDR (`IsContained` already returns that prefixLen). If none match that length, first containing ban CIDR in blob order. Same rule for captcha-only. Test two overlapping bans and assert one stored suffix.
  By: explore

- Q: Does resolving origin on a Range hit walk every CIDR (O(n)) and undo in-process membership?
  Decision: assumed — walk the cidr→stored map only after Helper reports a hit (drop path). Allow path stays two boolean tree lookups. Do not add Helper payload this change.
  By: explore

- Q: Must live/none Range lookups also carry origin?
  Decision: assumed — no. live/none skip `range-index` and use LAPI `?ip=`; `storeLiveDecision` already uses `RemediationWithOrigin`. Out of scope.
  By: explore
