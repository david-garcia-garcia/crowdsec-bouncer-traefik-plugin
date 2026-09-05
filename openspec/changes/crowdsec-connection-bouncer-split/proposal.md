## Why

One Traefik process cannot run two Crowdsec bouncer configs today: stream ticker, decision cache, and LAPI health are process globals, and `New` ignores Traefik’s context. Operators cannot compare configs side-by-side or attach two Crowdsec backends. First-wins is a bug, not a documented feature we keep.

## What Changes

- Thin the Yaegi root package to `CreateConfig` / `New`. `New` binds Traefik’s context through `pkg/reclaim` (copied from geoblock/modsecurity).
- Introduce `CrowdsecConnection` as the reclaim value (stream ticker, isolated cache, LAPI/CAPI HTTP, metrics, AppSec HTTP client) with `Close()`.
- Introduce `Bouncer` as `ForRoute(next)`: per-router request handling only.
- Connection identity is a hash of connection fields (not middleware name). Same backend shares one Connection; different backends/configs are two live Connections in one process.
- Drop the process-wide memory `ttl_map`. Each Connection has isolated cache space (private map; Redis key prefix).
- Tests: two configs in one process must not share ticker/cache/LAPI; mock e2e one Traefik / two middlewares / two LAPIs.

No **BREAKING** public JSON config keys.

## Capabilities

### New Capabilities

- `core_plugin_middleware_instance-reclaim`: Traefik `New` reclaims a `CrowdsecConnection` by connection-field key and returns a per-router Bouncer. Two different connection keys are two live cores in one process.
- `core_cache_client_isolated-store`: Each cache Client owns its memory map; Redis keys are prefixed with connection identity so two Connections do not share decisions, captcha grace, or the stream lease.
- `std_go_reclaim_context-lease`: Process reclaim table (`Open` / grace / `Close`) copied into this module for Yaegi-safe lifetime.
- `build_e2e_mock_dual-bouncer`: Mock e2e scenario: one Traefik, two bouncer middlewares, two LAPI mocks; each router follows its own config.

### Modified Capabilities

None.

## Impact

- `bouncer.go` split into root `plugin.go`, `pkg/crowdsecconnection`, `pkg/bouncer`.
- `pkg/cache` (drop package `ttl_map`; optional Redis prefix). In-tree `pkg/simpleredis` unchanged as the Redis dialect.
- New `pkg/reclaim` (stdlib only).
- `bouncer_test.go` / new package tests; `tests/e2e/mock/scenarios/` dual-bouncer.
- Yaegi still loads `CreateConfig`/`New` from module root (`.traefik.yml` import unchanged).
