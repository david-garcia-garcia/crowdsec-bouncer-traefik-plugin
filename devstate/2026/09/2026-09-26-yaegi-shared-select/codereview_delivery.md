# Delivery

## Motivation

Stream and metrics both enter one helper, `startTicker`. That helper starts a goroutine whose `select` waits on that call’s `ticker.C` and a buffered stop. `work()` runs on that goroutine. Sleep and Close send on both stop channels, then nil the fields. Wake and `startStream` start the loops again.

Traefik loads this plugin under yaegi v0.16.1. That interpreter builds a `select` case list once per statement and shares the slice across every goroutine that runs the statement, so the stream loop can wait on the metrics ticker (or the reverse). Upstream saw `GET /v1/decisions/stream` stall for about one or two metrics intervals while `POST /v1/usage-metrics` continued. Default `LapiMetricsUpdateIntervalSeconds` is `600`, so that stall is about 600s to 1200s. This tree still uses that shared `select`. Native isolation of the same two loops is a false green: the share is yaegi-only, and nothing here proved each loop stayed on its own channel under the interpreter Traefik actually uses.

Left alone, a Traefik deploy can stop refreshing CrowdSec decisions for ten to twenty minutes while still serving. Disabling metrics (`metricsUpdateIntervalSeconds: 0`) avoids the second loop but drops usage-metrics. The cross-wait is uncommon, but it is a live stream freeze, not a docs gap.

```mermaid
flowchart TD
    both[stream and metrics run the same select]
    share[yaegi v0.16.1 shares one case list]
    cross[one loop waits on the other ticker]
    stall[GET stream stalls 600s to 1200s]
    both --> share --> cross --> stall
```

Priority: P2 — real operator and end-user pain when stream poll stalls, with a disable-metrics workaround and a rare race

## Implementation

Keep `stopTicker` and the buffered stop. Split the loop into two source functions so each `select` is its own statement and gets its own yaegi case slice: `startStreamTicker` and `startMetricsTicker` create the ticker, spawn `runStreamTicker` / `runMetricsTicker`, and `defer ticker.Stop()`. Those run functions take injectable tick and stop channels; `work()` stays on that goroutine. `New`, `startStream`, and `Wake` call the matching start. Sleep and Close still `stopTicker` then nil. Do not range the ticker without a stop case (`Ticker.Stop` does not close `C`). Proof is a 20_000-send, `GOMAXPROCS>1` drive of the production loops under yaegi via `pkg/yaegitest.Run` (package `lapi` cannot load under `yaegi test`), plus a native test that stop ends both goroutines.

## What this changes
**Operators.** Stream poll under Traefik no longer freezes for one or two metrics intervals (default 600s) while usage-metrics continues; no new deploy key.
**Admin users.** None.
**Developers.** Stream and metrics ticker `select`s must stay distinct statements; `RunStreamTickerForTest` and `RunMetricsTickerForTest` are the exported drivers for that invariant.
**End users.** Requests in front of this middleware no longer ride a CrowdSec decision set that can sit stale for one or two metrics intervals while stream poll waits on the metrics ticker.
