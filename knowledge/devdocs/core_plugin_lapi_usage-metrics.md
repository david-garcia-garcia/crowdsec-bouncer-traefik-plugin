# LAPI usage-metrics

## Language

**Usage-metrics origin**:
The `origin` label on a LAPI usage-metrics item. CrowdSec `lists` origin is rewritten to `lists:` plus the decision scenario. Other CrowdSec origins stay as LAPI sent them. Drops with no decision use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, or `plugin:appsec_failure` so they show as origin rows in `cscli metrics show bouncers`.
_Avoid_: a `scenario` item label, `labels.type=traefik_plugin`, and reusing `crowdsec` / `cscli` / `appsec` for plugin fail-closed paths

**ip_type**:
`ipv4` or `ipv6` classified from an address `GetRemoteIP` already returned, or from a decision host/CIDR for the `active_decisions` gauge.
_Avoid_: parsing `RemoteAddr` on the metrics path

## Overview

Call `IncProcessed` and `IncDropped` from the bouncer on each handled request. Stream/alone also `rememberActiveDecision` / `forgetActiveDecision` when storing or deleting Ip, header, and Range records. The connection ticker POSTs `v1/usage-metrics`. `IncProcessed` is lock-free (`atomic.AddInt64`); `IncDropped` takes `metricsMu` because drops already left the allow path.

## How to use

- Classify `ip_type` with `ip.FamilyOfIP` on the `net.IP` GetRemoteIP already yielded (`client.ipType` on the request path). Do not parse `RemoteAddr`. Do not call `ip.Family` on the client string on the request path.
- Build origin with `MetricsOrigin(decision.Origin, decision.Scenario)` before cache store and before `IncDropped`.
- AppSec remediations use `origin=appsec`. Fail-closed drops use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, or `plugin:appsec_failure`.
- Persist origin on Ip/header cache via `cache.RemediationWithOrigin`. Range-index stays letter-only; range-only drops omit origin.
- Stamp `utc_startup_timestamp` once in `New` (`startedAt`). `feature_flags` must marshal as `[]`, not `{}`.

## Pattern snippet

```go
conn.IncProcessed(client.ipType)
conn.IncDropped(cache.RemediationOrigin(stored), client.ipType, "ban")
```

## Key files

- `pkg/crowdsecconnection/connection_metrics.go`
- `pkg/cache/remediation.go`
- `pkg/ip/network.go` (`Family`, `FamilyOfIP`, `FamilyOfHostOrCIDR`)
- `pkg/bouncer/bouncer.go`

## Gotchas

- `cscli metrics show bouncers` reads `origin` and `ip_type` only. Do not send a `scenario` label.
- `processed` is `ip_type` only and is incremented with `atomic.AddInt64` (no `metricsMu`). `dropped` may add `origin` and `remediation` and uses `metricsMu`. `active_decisions` is stream/alone only and counts records, not hosts in a CIDR.
- HTTP success from LAPI is 201.
