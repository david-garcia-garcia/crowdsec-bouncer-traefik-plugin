## Why

Traefik loads this plugin under yaegi v0.16.1. Stream and metrics both run the same `select` in `startTicker`. Yaegi builds that statement’s case list once and shares it across goroutines, so one loop can wait on the other loop’s ticker. Upstream [issue 377](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/377) shows `GET /v1/decisions/stream` stalling for about one or two metrics intervals while `POST /v1/usage-metrics` continues. [Pull request 399](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/399) ranged over the ticker and dropped stop because their stop channel was never signalled. This fork still signals that channel from Sleep and Close; `Ticker.Stop` does not close `C`, so copying 399 would leave those loops blocked after reclaim Sleep/Close.

## What Changes

- Split the shared `startTicker` loop into two distinct function bodies (stream vs metrics). Each `select`s on that loop’s `ticker.C` and buffered stop. `work()` stays on the ticker goroutine. `stopTicker` stays the non-blocking send.
- Do not copy PR 399’s `for range ticker.C` / return `*time.Ticker`. Out of scope: `Ticker.Stop` does not close `C`.
- Isolation test in `pkg/lapi/zzz_ticker_own_channel_test.go`: must fail under yaegi v0.16.1 when both loops share one `select` statement, and pass when each loop has its own. Native `go test` covers Sleep/Close stop; it is not proof of the yaegi bug.
- Fold the live promise into the two leaves that already name `startTicker`. Do not add a ticker spec leaf.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_stream-single-flight`: stream ticker `select` is a distinct statement from metrics; `work()` still runs on the ticker goroutine; two copies of the helper are not a third poll loop; stop channel stays.
- `core_plugin_lapi_usage-metrics`: Sleep/Wake/Close start and stop the metrics ticker with that distinct body, not the shared `startTicker` `select`; `stopTicker` unchanged.

## Impact

- `pkg/lapi/client.go` (`startTicker` / `stopTicker`, `New` / `Sleep` / `Wake` / `Close` wiring).
- `pkg/lapi/client_stream.go` (`startStream`).
- Tests: `pkg/lapi/zzz_ticker_own_channel_test.go` (new); native Sleep/Close coverage in `pkg/lapi` (`TestSleepDrainsMetrics` / `TestCloseDrainsMetrics` plus stop).
- Catalog leaves `openspec/specs/core_plugin_lapi_stream-single-flight` and `openspec/specs/core_plugin_lapi_usage-metrics`.
- Usage packets `knowledge/devdocs/core_plugin_lapi_stream-single-flight.md` and `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` still say `startTicker`; update after apply (devdocsimpact).
- No **BREAKING** public JSON/YAML keys.
- Out of scope: stream poll, usage-metrics POST body, reclaim Sleep/Wake/Close beyond ticker stop, copying PR 399 range-without-stop, a third ticker spec leaf.
