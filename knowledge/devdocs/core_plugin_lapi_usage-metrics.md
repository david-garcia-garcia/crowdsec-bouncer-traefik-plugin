# LAPI usage-metrics

## Language

**Usage-metrics origin**:
The `origin` label on a LAPI usage-metrics item. CrowdSec `lists` origin is rewritten to `lists:` plus the decision scenario. Other CrowdSec origins stay as LAPI sent them. Drops with no decision use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, or `plugin:appsec_failure` so they show as origin rows in `cscli metrics show bouncers`.
_Avoid_: a `scenario` item label, `labels.type=traefik_plugin`, and reusing `crowdsec` / `cscli` / `appsec` for plugin fail-closed paths

**ip_type**:
`ipv4` or `ipv6` classified from an address `GetRemoteIP` already returned, or from a decision host/CIDR for the `active_decisions` gauge.
_Avoid_: parsing `RemoteAddr` on the metrics path

**MetricsReporter**:
The owner of one Client's usage-metrics window (dropped counters, processed atomics, active_decisions gauge, last successful push) and the POST/restore path. Client holds one pointer for the reclaim lifetime; tickers stay on Client.
_Avoid_: a second reclaim key, a reporter-owned `*http.Client`, a second metrics ticker

## Overview

Call `IncProcessed` and `IncDropped` from the bouncer on each handled request. Stream/alone also `rememberActiveDecision` / `forgetActiveDecision` when storing or deleting Ip, header, and Range records. The Client ticker POSTs `v1/usage-metrics` through the `MetricsReporter` Client holds. `IncProcessed` is lock-free (`atomic.AddInt64`); `IncDropped` takes the reporter `metricsMu` because drops already left the allow path.

## How to use

- Classify `ip_type` with `ip.FamilyOfIP` on the `net.IP` GetRemoteIP already yielded (`req.ipType` on the request path). Do not parse `RemoteAddr`. Do not call `ip.Family` on the client string on the request path.
- Build origin with `MetricsOrigin(decision.Origin, decision.Scenario)` before cache store and before `IncDropped`.
- AppSec remediations use `origin=appsec`. Fail-closed drops use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, or `plugin:appsec_failure`.
- Persist leftover origin on Ip/header and Range-index via `decisionscope.RemediationWithOrigin`. Packed memory values use the DecisionStore intern table. Bare letter-only Range lines still match and MAY omit origin. `activeDecisionSlots` stores `originID` + family; POST still emits origin names.
- Construct one `MetricsReporter` in `New` (`newMetricsReporter`). Bind `query` to `crowdsecQuery`. Do not store `*http.Client` on the reporter.
- Stamp `utc_startup_timestamp` once on the reporter at construct. Do not use `time.Now()` at each push. `feature_flags` must marshal as `[]`, not `{}`.
- Keep `IncProcessed` / `IncDropped` / `rememberActiveDecision` / `forgetActiveDecision` as `Client` methods (thin forwards). A Client literal without a reporter no-ops those methods.
- Keep `metricsInterval` on Client. Start and stop the existing metrics ticker with `startTicker` in `New` / `Sleep` / `Wake` / `Close`. Do not open a second reclaim entry or a second metrics ticker.
- In `zzz_metrics_test.go`, call `attachTestMetricsReporter` after `attachTestTransport`. Stamp `startedAt` on the reporter, not on Client.

## Pattern snippet

```go
lapiClient.IncProcessed(req.ipType)
lapiClient.IncDropped(decisionscope.RemediationOrigin(stored), req.ipType, "ban")
```

## Key files

- `pkg/lapi/client_metrics.go`
- `pkg/lapi/client.go` (`metricsReporter` field and ticker wiring)
- `pkg/decisionscope/remediation.go`
- `pkg/ip/network.go` (`Family`, `FamilyOfIP`, `FamilyOfHostOrCIDR`)
- `pkg/bouncer/bouncer.go`

## Gotchas

- `cscli metrics show bouncers` reads `origin` and `ip_type` only. Do not send a `scenario` label.
- `processed` is `ip_type` only and is incremented with `atomic.AddInt64` (no `metricsMu`). `dropped` may add `origin` and `remediation` and uses `metricsMu`. `active_decisions` is stream/alone only and counts records, not hosts in a CIDR.
- HTTP success from LAPI is 201.
- Sleep and Close POST the remaining window (`drainMetrics`) so a Traefik reload does not drop counters. Sleep drains in a goroutine (reclaim holds the table lock). Close drains synchronously before idle HTTP is closed. A failed POST restores the window for the next drain or ticker. `metricsInterval == 0` skips drain.
- The reporter POSTs through the injected query (`crowdsecQuery` loads `currentTransport()`). Window counters survive `AdoptTransport`. Do not put `*http.Client` on the reporter.
- `New` always sets the reporter. Client literals in other packages may have a nil reporter; forwards return without counting.
