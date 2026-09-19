## Context

See proposal.md — Why. Stream Range upserts store `RemediationValue(type)` (letter). `range-index` lines are `cidr=t`. `RangeMembership` is two boolean Helpers; `Remediation` returns bare `t`/`c`. `LookupCachedRemediation` then has empty origin for Range-only. `PreferRemediation` already keeps a ban’s suffix. `parseIndexLine` splits on the first `=`. Gauge origin already comes from `rememberActiveDecision`. Client IP is `pkg/ip.GetRemoteIP`. Origin at apply is `MetricsOrigin(decision.Origin, decision.Scenario)`.

## Goals / Non-Goals

**Goals:**
- Range-only drops and lookup origin match Ip/header (`t`/`c` + U+001F + MetricsOrigin).
- Bare `cidr=t` still bans.
- Redis stays one `range-index` key.

**Non-Goals:**
- Per-CIDR keys or expanding a CIDR into host keys.
- Payload on `iplookup.Helper`.
- Changing `rememberActiveDecision` / `active_decisions`.
- live/none Range path (already uses `RemediationWithOrigin` on LAPI `?ip=`).
- Public config.

## Decisions

1. **Stream Range upsert uses `RemediationWithOrigin`.** Same codec as Ip/header. Alternative: a second origin map — rejected; Redis would need another key.

2. **Helper stays boolean.** `MembershipFromIndex` keeps a cidr→stored map. After `IsContained` hits, resolve the stored string of the longest-prefix matching CIDR of that kind (`prefixLen` from Helper). Allow path stays two tree lookups. Alternative: Helper payload — out of scope.

3. **Lookup does not grow a third return.** Membership returns the suffixed string; `PreferRemediation` and `RemediationOrigin` already split it. Update the Range-only-empty comment.

4. **Identity:** reuse `GetRemoteIP` and apply-time `MetricsOrigin`. Do not parse `RemoteAddr` or reconstruct origin at lookup.

## Risks / Trade-offs

- [Overlapping bans, different origins] → longest-prefix CIDR wins; documented on explore.md. Test two overlapping bans and assert one stored suffix.
- [O(n) map walk on Range hit] → accepted on the drop path only. Do not walk on miss.
- [U+001F in the blob] → not `=` and not newline; `parseIndexLine` already preserves the suffix.
- [Old Redis letter-only] → `RemediationKind` / `IsActiveRemediation` still match; origin MAY be empty.

## Migration Plan

Plugin version bump. No new YAML keys. Existing `range-index` letter-only lines keep banning. New stream ticks rewrite CIDRs with suffix. Rollback is the previous tag (origin on Range-only drops goes empty again).

## Open Questions

None. Assumed proceed policies live on `devstate/explore.md`.
