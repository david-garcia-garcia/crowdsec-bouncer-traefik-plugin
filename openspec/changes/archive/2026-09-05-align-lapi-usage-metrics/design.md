## Context

`reportMetrics` POSTs one unlabeled `dropped` count. Research `knowledge/research/ext_crowdsec_lapi_usage-metrics/` (CrowdSec `@909b5157`): LAPI stores any labels; `cscli metrics show bouncers` reads only `origin` and `ip_type`. Official Lua/firewall send `dropped`, `processed`, `active_decisions`. List identity is `origin=lists:<scenario>`, not a `scenario` label. Client address owner is `pkg/ip.GetRemoteIP`.

## Goals / Non-Goals

**Goals:**

- Match official bouncer usage-metrics names and the labels cscli displays
- Keep decision matching keys and reclaim identity unchanged
- Count processed on trusted-IP bypass as well as pass/drop

**Non-Goals:**

- Traefik Prometheus metrics
- A `scenario` item label
- Expanding Range CIDRs into per-host `active_decisions`
- Live/none `active_decisions` (TTL expiry cannot decrement a gauge)
- Changing User-Agent or reclaim key

## Decisions

- Origin rewrite for `lists` happens when storing the decision (`MetricsOrigin(origin, scenario)`), not at cscli.
- Cache value grammar: `letter` or `letter` + U+001F + origin. Owned by `pkg/cache` next to `BannedValue`.
- `ip_type` is `ip.Family(remoteIP)` on the string `GetRemoteIP` already returned.
- Range-only hits have no origin on `dropped` unless the same request also hits an Ip/header value that carries origin (range-index stays `cidr=letter` so membership helpers stay two boolean sets).
- `active_decisions` only in stream/alone, one count per stored decision record / Range CIDR.
- Metrics maps live on CrowdsecConnection (shared ticker). Bouncer only increments.

## Risks / Trade-offs

- Old Redis values without origin still match; those drops omit `origin` until the next stream upsert — acceptable.
- Range drops omit origin — smaller than teaching RangeMembership to track per-CIDR origin.
- Empty `origin` is omitted from cscli table rows but still in totals — same as official `processed`.
