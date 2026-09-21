## Context

See `proposal.md` — Why. On `master`, stream and live call `decisionscope.RemediationValue(decision.Type)` only. `MetricsOrigin` already rewrites `lists` + scenario to `lists:<name>` for stored origin and usage-metrics. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/369 remaps on raw `Origin` inside `bouncer.go`; this fork’s apply lives in `pkg/lapi`.

## Goals / Non-Goals

**Goals:**

- Empty `banToCaptchaOrigins` is a complete no-op.
- Listed-origin bans store captcha kind `c` on Ip, header-scope, and Range stream writes and on live/none query/cache.
- Config `lists` matches every list metrics origin; `lists:<name>` matches one list.
- Live strongest pick prefers a decision that still maps to ban.

**Non-Goals:**

- ServeHTTP remap, raw `origin` match without `MetricsOrigin`, Open-key hashing of the list, ValidateParams origin enum, ticker-stop, AppSec.

## Decisions

1. **Match `MetricsOrigin` output** — Owner of the origin string is `MetricsOrigin` (`pkg/lapi/client_metrics.go`). Alternative (upstream raw `Origin`) cannot distinguish lists.

2. **Helper on `lapi.Client`** — Stream and live already map type→kind there. Alternative (Bouncer ServeHTTP) would store `t` for listed bans and break Range/live ban-over-captcha.

3. **First-create residue** — Copy the list in `New`. Do not add it to `SessionKey` / live `Key` (would split the stream poller). Same class as `updateMaxFailure`.

4. **Exact match plus `lists` prefix** — `entry == metricsOrigin`, or `entry == "lists"` and origin is `lists` or has prefix `lists:`. No case-fold.

5. **No provider coupling** — Captcha without provider already falls back to ban rendering.

## Risks / Trade-offs

- **[Risk] Two routers share a Client with different lists** → Mitigation: first `New` wins; document. Do not union (would surprise the other router).
- **[Trade-off] Changing the list needs a process restart to replace the Client** → Same as other first-create scalars; reload ticker-stop is out of scope.

## Migration Plan

Empty default. Existing deploys unchanged until operators set `banToCaptchaOrigins`. Stored kinds rewrite on the next stream payload / live TTL.

## Open Questions

None — explore resolved live remap, validation, match rules, and reclaim-key exclusion.
