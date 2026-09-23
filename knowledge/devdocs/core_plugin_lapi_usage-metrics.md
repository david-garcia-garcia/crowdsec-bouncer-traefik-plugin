# LAPI usage-metrics

## Language

**Usage-metrics origin**:
The `origin` label on a LAPI usage-metrics item. CrowdSec `lists` origin is rewritten to `lists:` plus the decision scenario. Other CrowdSec origins stay as LAPI sent them. Drops with no decision use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, `plugin:appsec_failure`, or `plugin:forced_decision` so they show as origin rows in `cscli metrics show bouncers`.
_Avoid_: a `scenario` item label, `labels.type=traefik_plugin`, and reusing `crowdsec` / `cscli` / `appsec` for plugin fail-closed paths

**ip_type**:
`ipv4` or `ipv6` classified from an address `GetRemoteIP` already returned, or from a decision host/CIDR for the `active_decisions` gauge.
_Avoid_: parsing `RemoteAddr` on the metrics path

**MetricsReporter**:
The owner of one Client's usage-metrics window (dropped counters, processed atomics, last successful push) and the POST/restore path. Stream/alone `active_decisions` is a DecisionStore snapshot at POST. Client holds one pointer for the reclaim lifetime; tickers stay on Client.
_Avoid_: a second reclaim key, a reporter-owned `*http.Client`, a second metrics ticker, a reporter-held forget map

**Compact decision slot**:
One DecisionStore origin-id × family count: intern `originID` plus address family. Intern overflow leaves `originID` 0 so POST emits an empty origin. Range is omitted from this gauge.
_Avoid_: leftover origin string, storing the origin name on every slot, a reporter `activeDecisionSlots` map

## Overview

Call `IncProcessed` and `IncDropped` from the bouncer on each handled request. Stream/alone `active_decisions` is a DecisionStore snapshot at POST (memory recounts after PublishTick; Redis is empty). The Client ticker POSTs `v1/usage-metrics` through the `MetricsReporter` Client holds. `IncProcessed` is lock-free (`atomic.AddInt64`); `IncDropped` takes the reporter `metricsMu` because drops already left the allow path.

## How to use

- Classify `ip_type` with `ip.FamilyOfIP` on the `net.IP` GetRemoteIP already yielded (`req.ipType` on the request path). Do not parse `RemoteAddr`. Do not call `ip.Family` on the client string on the request path.
- Build origin with `MetricsOrigin(decision.Origin, decision.Scenario)` before Store Put and before `IncDropped`.
- AppSec remediations use `origin=appsec`. Fail-closed drops use `plugin:tech_getremotefail`, `plugin:tech_trustipfail`, `plugin:tech_cachefail`, `plugin:tech_streamfail`, `plugin:lapi_failure`, or `plugin:appsec_failure`. Forced `crowdsecDecisionHeader` drops use `plugin:forced_decision`.
- Persist origin on Redis Ip/header and Range-index via `KindOriginString`. Packed memory values use the DecisionStore intern table. Overflow Warns and keeps origin id 0 (`OriginName` empty). Bare letter-only Range lines still match and MAY omit origin. `ActiveCounts` is intern id + family; POST emits `OriginName(originID)` only.
- Construct one `MetricsReporter` in `New` (`newMetricsReporter`). Bind `query` to `crowdsecQuery`. Do not store `*http.Client` on the reporter. The reporter logger is the LAPI constructor `log.With` child (`std_go_logger_nested`); do not pass `sessionKey` on `reportMetrics`.
- Stamp `utc_startup_timestamp` once on the reporter at construct. Do not use `time.Now()` at each push. `feature_flags` must marshal as `[]`, not `{}`.
- Keep `IncProcessed` / `IncDropped` as `Client` methods (thin forwards). A Client literal without a reporter no-ops those methods.
- Keep `metricsInterval` on Client. Start and stop the existing metrics ticker with `startTicker` in `New` / `Sleep` / `Wake` / `Close`. Do not open a second reclaim entry or a second metrics ticker.
- In `zzz_metrics_test.go`, call `attachTestMetricsReporter` after `attachTestTransport`. Stamp `startedAt` on the reporter, not on Client.

## Pattern snippet

```go
kind, origin, originID, err := lapiClient.LookupRemediation(req.remoteIP, req.ipAddr, scopes)
if origin == "" {
	origin = lapiClient.OriginName(originID)
}
lapiClient.IncProcessed(req.ipType)
lapiClient.IncDropped(origin, req.ipType, "ban")
```

## Key files

- `pkg/lapi/client_metrics.go`
- `pkg/lapi/client.go` (`metricsReporter` field and ticker wiring)
- `pkg/decisionstore/pack.go`
- `pkg/ip/network.go` (`Family`, `FamilyOfIP`, `FamilyOfHostOrCIDR`)
- `pkg/bouncer/bouncer.go`

## Gotchas

- `cscli metrics show bouncers` reads `origin` and `ip_type` only. Do not send a `scenario` label.
- `processed` is `ip_type` only and is incremented with `atomic.AddInt64` (no `metricsMu`). `dropped` may add `origin` and `remediation` and uses `metricsMu`. `active_decisions` is stream/alone only and counts records, not hosts in a CIDR. Range CIDRs stay out of the gauge. Memory recounts after PublishTick (expired slots drop). Redis posts an empty gauge.
- HTTP success from LAPI is 201.
- Sleep and Close POST the remaining window (`drainMetrics`) so a Traefik reload does not drop counters. Sleep drains in a goroutine (reclaim holds the table lock). Close drains synchronously before idle HTTP is closed. A failed POST restores the window for the next drain or ticker. `metricsInterval == 0` skips drain.
- The reporter POSTs through the injected query (`crowdsecQuery` loads `currentTransport()`). Window counters survive `AdoptTransport`. Do not put `*http.Client` on the reporter.
- `New` always sets the reporter. Client literals in other packages may have a nil reporter; forwards return without counting.
