# LAPI usage-metrics

## Language

**Usage-metrics origin**:
The `origin` label on a LAPI usage-metrics item. CrowdSec `lists` origin is rewritten to `lists:` plus the decision scenario. Other origins stay as LAPI sent them.
_Avoid_: a `scenario` item label, `labels.type=traefik_plugin`

**ip_type**:
`ipv4` or `ipv6` classified from an address `GetRemoteIP` already returned, or from a decision host/CIDR for the `active_decisions` gauge.
_Avoid_: parsing `RemoteAddr` on the metrics path

## Overview

Call `IncProcessed` and `IncDropped` from the bouncer on each handled request. Stream/alone also `rememberActiveDecision` / `forgetActiveDecision` when storing or deleting Ip, header, and Range records. The connection ticker POSTs `v1/usage-metrics`.

## How to use

- Classify `ip_type` with `ip.Family` on the GetRemoteIP string. Do not parse `RemoteAddr`.
- Build origin with `MetricsOrigin(decision.Origin, decision.Scenario)` before cache store and before `IncDropped`.
- AppSec remediations use `origin=appsec`. Technical/failure drops omit origin.
- Persist origin on Ip/header cache via `cache.RemediationWithOrigin`. Range-index stays letter-only; range-only drops omit origin.
- Stamp `utc_startup_timestamp` once in `New` (`startedAt`). `feature_flags` must marshal as `[]`, not `{}`.

## Pattern snippet

```go
conn.IncProcessed(ip.Family(remoteIP))
conn.IncDropped(cache.RemediationOrigin(stored), ip.Family(remoteIP), "ban")
```

## Key files

- `pkg/crowdsecconnection/connection_metrics.go`
- `pkg/cache/remediation.go`
- `pkg/ip/network.go` (`Family`, `FamilyOfHostOrCIDR`)
- `pkg/bouncer/bouncer.go`

## Gotchas

- `cscli metrics show bouncers` reads `origin` and `ip_type` only. Do not send a `scenario` label.
- `processed` is `ip_type` only. `dropped` may add `origin` and `remediation`. `active_decisions` is stream/alone only and counts records, not hosts in a CIDR.
- HTTP success from LAPI is 201.
