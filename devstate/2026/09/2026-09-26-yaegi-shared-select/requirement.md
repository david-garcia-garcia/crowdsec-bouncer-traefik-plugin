# Requirement
IssueKey: 2026-09-26-yaegi-shared-select

## Problem

Traefik loads this plugin under yaegi. Stream and metrics both run the same `select` inside `startTicker`. Upstream issue 377 / pull request 399 report that yaegi v0.16.1 builds that `select`'s case list once per statement and shares it across every goroutine that runs the statement, so one loop can wait on the other loop's ticker. Observed upstream: stream `GET /v1/decisions/stream` stalls for about one or two metrics intervals while `POST /v1/usage-metrics` continues (or the reverse). This fork still uses that shared `select` and still signals its stop channel from Sleep and Close, so copying pull request 399's range-over-ticker (no stop) would leave Sleep and Close unable to end the loops.

## Current (code)

- `.traefik.yml` — Traefik middleware plugin manifest (`type: middleware`). `.github/workflows/main.yml` — Traefik 3.x bundles yaegi v0.16.1; CI `YAEGI_VERSION` is `v0.16.1`. `Makefile` `yaegi_test` runs `yaegi test -v .`. `pkg/yaegitest/interpreter.go` — runs a program under the yaegi v0.16.1 binary the way Traefik loads this module.
- `pkg/lapi/client.go` `startTicker` — one `select` on `ticker.C` and a buffered `stop` chan; `work()` runs on that goroutine. Stream and metrics both call this helper (`pkg/lapi/client_stream.go` `startStream`; `pkg/lapi/client.go` `New` and `Wake`).
- `pkg/lapi/client.go` `stopTicker` — non-blocking send on that stop chan. `Sleep` and `Close` both call `stopTicker` on `streamStop` and `metricsStop`, then nil the fields.
- `pkg/lapi/client_http.go` — stream poll route `v1/decisions/stream`. `pkg/lapi/client_stream.go` `handleStreamTicker` — ticker work for stream. `pkg/lapi/client_metrics.go` — metrics route `v1/usage-metrics`; `handleMetricsTicker` is the metrics ticker work.
- `pkg/configuration/configuration.go` — default `LapiMetricsUpdateIntervalSeconds` is `600`.
- Yaegi sharing one `select` case list across goroutines that run the same statement — not found (yaegi is not vendored in this tree).
- Upstream pull request 399 range-over-ticker / return `*time.Ticker` — not found.
- `Test_runTicker_keepsEachTickerOnItsOwnChannel` — not found.

## Desired

An OpenSpec change for a yaegi-safe ticker loop used by stream and metrics, which still stops when Sleep or Close signals stop, plus test coverage that shows each loop receives only its own ticks. The proposal cites https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377 and https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399.

## Affected

- `pkg/lapi/client.go` — `startTicker` / `stopTicker` and Sleep / Close / Wake / New wiring.
- `pkg/lapi/client_stream.go` — stream ticker start.
- Tests under `pkg/lapi` (or yaegi test helper) that prove each loop stays on its own channel — not found yet.
- OpenSpec change folder — not found yet (propose owns it).

## Out of scope

- Copying pull request 399 as-is (drop the stop channel, return `*time.Ticker`).
- Changing stream poll, usage-metrics POST, reclaim Sleep/Wake/Close beyond what the ticker loop needs.
- Product code in this prepare phase.

## Unknowns

- How yaegi v0.16.1 (and current yaegi master) actually shares `select` cases; whether native `go test` can show the race.
- How upstream's stop channel differs from this fork's Sleep/Close signalling, and what stop-safe loop shape matches both (range, two functions, duplicated select, or something else).
- The fix design. Explore owns these.

## Tensions

- Pull request 399 replaced the shared `select` with `range` over the ticker and stopped returning a stop chan because theirs was never signalled. This tree signals that chan from Sleep and Close. Honouring the upstream patch letter would drop a path this fork uses.
