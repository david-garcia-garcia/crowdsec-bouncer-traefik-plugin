# Explore
IssueKey: 2026-09-05-improve-metrics

## Concepts

**Usage-metrics push**: CrowdsecConnection POSTs `v1/usage-metrics` on a ticker. Not Traefik Prometheus. Owner: `reportMetrics`. Official packet: `knowledge/research/ext_crowdsec_lapi_usage-metrics/`.

**Item labels vs component identity**: LAPI stores any `labels` map. `cscli metrics show bouncers` reads only `origin` and `ip_type`. Row `type`/`version` come from User-Agent `Crowdsec-Bouncer-Traefik-Plugin/<version>`, not from the JSON `type` field. Payload `name` is unused for the bouncer row.

**Origin (not scenario)**: Official bouncers do not send a `scenario` label. When a decision origin is `lists`, they rewrite origin to `lists:` + the decision's scenario (list name). Other origins stay `crowdsec` / `CAPI` / `cscli` / `appsec` / … Firewall comments say other scenarios are too noisy.

**ip_type**: `ipv4` or `ipv6` from the already-resolved client address (`pkg/ip.GetRemoteIP`). Do not parse `RemoteAddr` again.

**Remediation letter**: Cache stores `t`/`c`/`f`/`d` only. `Decision.Origin`, `Scenario`, `Type` are dropped at `storeStreamDecision` / live cache. Request-time `IncBlocked` cannot slice by origin today.

```
LAPI Decision {origin, scenario, type}
        │
        ▼ storeStreamDecision
   cache value  "t"|"c"     ← origin/scenario discarded
        │
        ▼ ServeHTTP hit
   IncBlocked()             ← scalar, no labels
        │
        ▼ reportMetrics
   one item: dropped + labels.type=traefik_plugin
```

Official Lua / firewall:

```
dropped     unit request|byte|packet   labels origin + ip_type
processed   unit request|byte|packet   labels ip_type (origin omitted)
active_decisions  unit ip              labels origin + ip_type
```

## Decisions

- Reproduce first: the current POST is one `dropped`/`request` item with `labels.type=traefik_plugin`, no `origin`/`ip_type`/`scenario`. User-Agent `Crowdsec-Bouncer-Traefik-Plugin/<version>`. `utc_startup_timestamp` is `time.Now()` at push, same second as `utc_now_timestamp` in the probe.
- Follow official bouncers and `cscli` display, not a new `scenario` label, unless the human overrides.
- Client address owner is `pkg/ip.GetRemoteIP`. `ip_type` is classified from that string.
- Do not change decision matching (IP/Range/header). Cache value may grow so drop-time metrics can still match.
- Metrics stay on CrowdsecConnection (shared ticker). Bouncer only reports what happened on a request (increment). No `sync.Once`.

## Open questions

- Q: The ticket asked to slice by scenario. LAPI will store a `scenario` label, but `cscli metrics show bouncers` never displays it. Official bouncers fold list names into `origin` as `lists:<scenario>`.
  Decision: assumed — send official labels `origin` and `ip_type` (and `remediation` when the drop is ban vs captcha). For list decisions, set `origin` to `lists:` + scenario. Do not send a `scenario` label as the primary slice.
  By: explore

- Q: Should this plugin also send `processed` and `active_decisions` (the other two names official docs intend and cscli aggregates)?
  Decision: assumed — yes. `processed` = every enabled request (trusted bypass, pass, drop), `ip_type` only. `active_decisions` = stream/alone gauge of stored decision records (Ip, header, Range CIDRs), not expanded hosts; live/none omit the gauge (TTL cannot decrement).
  By: propose

- Q: What origin (if any) for AppSec drops, failure-action bans, and stream-unhealthy remediations that have no LAPI decision?
  Decision: assumed — AppSec structured/ban/challenge → `origin=appsec`. Failure-action / stream-unhealthy / redis-tech with no decision → `dropped` with `ip_type` (and `remediation`) and **empty origin** so cscli still totals them but does not invent an origin bucket. Do not invent `origin=plugin`.
  By: explore

- Q: Stream/live cache currently stores only a remediation letter. Origin/scenario needed at drop time will be missing on cache hits unless we persist them.
  Decision: assumed — persist origin (after lists-rewrite) on Ip and header cache values as letter + U+001F + origin. Range-index stays `cidr=letter` (range-only drops omit origin). ip_type from GetRemoteIP at request. Matching keys unchanged.
  By: propose

- Q: Who owns the client address used for `ip_type`?
  Decision: resolved — `pkg/ip.GetRemoteIP` already computed the client IP. Classify that output (`net.ParseIP` To4 vs v6). Do not parse `RemoteAddr` on the metrics path.
  By: explore

- Q: `labels.type=traefik_plugin` today occupies a slot cscli never reads. Is it required identity?
  Decision: assumed — drop that item label. Component identity stays User-Agent plus payload `type`/`name`/`version`. JSON `type` stays `bouncer` unless we later align with a CrowdSec-catalog name.
  By: explore

- Q: `utc_startup_timestamp` is rewritten to `time.Now()` on every push (probe: same unix second as `utc_now_timestamp`).
  Decision: assumed — stamp connection start once in `New` and send that. In scope of the same envelope.
  By: explore
