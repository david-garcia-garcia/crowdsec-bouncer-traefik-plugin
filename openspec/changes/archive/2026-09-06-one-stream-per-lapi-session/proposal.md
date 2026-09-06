## Why

CrowdSec `GET /v1/decisions/stream` is one cursor on the bouncer row (hashed API key + client IP). This plugin reclaimed `CrowdsecConnection` by a hash that included intervals, Redis, TLS extras, and AppSec. Two stream middlewares with the same LAPI key and different knobs started two tickers, stole deltas, and each wrote an isolated cache. E2e papered it by copying `metricsUpdateIntervalSeconds`. Isolated backends still need a second bouncer key.

## What Changes

- Stream/alone session prefix (cache + `PeekLivePrefix`) is the **stream session** (LAPI URL + key, or CAPI machine+password in alone). Reclaim `Open` key is that prefix plus a settings-snapshot hash so a sleeper does not occupy a new snapshot’s slot.
- One stream ticker and one cache prefix per session in a Traefik process. A second **live** middleware on that session is **warn-and-wire** via `PeekLivePrefix`: log owner name, joiner name, and ignored knobs; bind the existing connection. Do not start a second poller.
- Traefik reload with an **unchanged** snapshot Sleeps (tickers off) then Wakes (`startup=false`). Grace only keeps that key peekable.
- Reload with a **changed** snapshot and no live holder: `Open` the new key (create). The old sleeper dies on grace Close. Callers do not Close slots.
- Redis/memory prefix for stream/alone follows the session. Live/none keep today’s full identity key (no stream cursor).
- Comments in code explain LAPI cursor ownership (key+IP), why two pollers are invalid, and Sleep/Wake vs grace Close.

No **BREAKING** public JSON config keys. Different `decisionScopeHeaders` on the same key first-wins (logged); a second bouncer key remains the isolation path.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: session prefix + settings-hash reclaim key; warn-and-wire via `PeekLivePrefix`; Sleep/Wake; new snapshot while sleeping opens a new key.
- `std_go_reclaim_context-lease`: `Peek` and `PeekLivePrefix`; last holder Sleeps; Open during grace Wakes; grace Close()s.
- `core_cache_client_isolated-store`: stream/alone Redis prefix is the session hex, not the extra-knob identity hash.

## Impact

- `pkg/crowdsecconnection` session prefix, settings-hash `SessionKey`, `OpenStream`, warn log.
- `plugin.go` stream/alone vs live/none reclaim path.
- `pkg/reclaim` `Peek` / `PeekLivePrefix` / Sleep-Wake.
- Specs and usage `core_plugin_middleware.md`, `build_e2e_real.md`, `core_cache_client.md`.
- Tests: same LAPI key + different metrics share one ticker; snapshot change during grace stops the old ticker first; different LAPI hosts still isolated.
- E2e: `/trusted` need not copy `/stream` metrics interval.
