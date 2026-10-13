---
url: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/blob/04d928872df12bdb9d953b2d92948e0b89692d6a/bouncer.go
title: bouncer.go stream/live/AppSec failure paths
fetched: 2026-09-05
authority: source
ref: github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin@04d928872df12bdb9d953b2d92948e0b89692d6a:bouncer.go
---

Globals start isCrowdsecStreamHealthy=true, updateFailure=0.

handleStreamTicker: on stream update error, if updateMaxFailure != -1 and updateFailure >= updateMaxFailure and currently healthy, set isCrowdsecStreamHealthy=false. Then increment updateFailure. On success, healthy=true and updateFailure=0. Default updateMaxFailure 0 → first failed poll marks unhealthy.

ServeHTTP stream/alone: cache miss + healthy → allow (not in ban list). Cache miss + unhealthy → handleBanServeHTTP ReasonTECH (block all).

ServeHTTP live: handleNoStreamCache. crowdsecQuery error returns BannedValue+err; ServeHTTP treats non-NoBannedValue as remediation (ban).

crowdsecQuery: transport error or HTTP 502/503/504 → crowdsecQuery:unreachable. Non-2xx → error. Live path fail-closed. No lapi_failure_action.

appsecQuery: unreachable (error or 502/503/504) gated by appsecUnreachableBlock; 500 gated by appsecFailureBlock; other non-200 including 401/403 → error → ban.

StreamStartupBlock true: New() calls handleStreamTicker synchronously before serving.
