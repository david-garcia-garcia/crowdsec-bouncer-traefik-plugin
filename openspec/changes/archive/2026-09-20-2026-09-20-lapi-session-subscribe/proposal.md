## Why

DestBranch hashes Redis store params into the stream/alone Client Open key, so two middlewares that share one CrowdSec bouncer row (hashed API key + this process’s outbound IP) can still run two `GET /v1/decisions/stream` tickers and two usage-metrics windows. CrowdSec stores one cursor and one metrics window on that row; Redis disagreement is not isolation.

## What Changes

- Stream/alone reclaim key becomes the LAPI session only: `lapi:stream:` plus `SessionHex` (mode + scheme/host/path + lapiKey, CAPI in alone). Not Redis, not middleware name, not outbound IP, not LAPI host alone.
- Join vs reconfigure stays reclaim table state (live bind / Sleep+Wake / empty create). Subscribe reuses the live Client and its child DecisionStore. Do not fail `New`. Do not Peek. Do not `startup=true` because YAML changed.
- Client records live holder middleware names as a set (constructor ctx → Traefik `name`, same shape as `liveHeaderScopes`). WARN on subscribe/Wake mismatch lists every ignored session-owned field, the distinct holder names, and that isolation needs a second bouncer API key.
- Session-owned first-wins (at least): Redis knobs, `updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, CAPI scenarios. Per-router policy stays on Bouncer. TLS/timeout stay `AdoptTransport` last-wins. `decisionScopeHeaders` stay live union.
- Wake with a Redis YAML change keeps the live store and WARNs; no memory↔Redis migrate.
- DecisionStore is constructed in Client `create()`, not a sibling reclaim Open. Client Close Closes the store. Sleep/Wake keep it. Redis keys stay prefixed with `SessionHex` (no key migration).
- First-create INFO: this LAPI key owns the process-wide stream and metrics window. README: one key = one ticker + one metrics window in this instance; Redis/interval disagreements are ignored, not isolated. Two Traefik processes remain docs-only (reclaim is process-local).
- Live/none `Key` still includes Redis and `MetricsUpdateIntervalSeconds`. Stream and live do not share one Client or one `MetricsReporter`.

Not **BREAKING** for operators: public Traefik YAML keys stay. Behavior change: Redis disagreement no longer opens a second stream ticker.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_reclaim-key`: Stream/alone Open key drops the Redis hash; subscribe/Wake first-wins session-owned knobs with WARN (fields + holder names + second API key); holder-name set; README contract.
- `core_plugin_decisionstore_store`: Store is a child of Client `create()`, not a sibling reclaim Open; Client Close Closes the store; Redis prefix stays `SessionHex`.
- `core_plugin_middleware_bouncer`: `New` no longer Opens DecisionStore as a separate reclaim holder; failed `New` still releases the LAPI Client (store Close is that Client’s Close hook).
- `core_plugin_lapi_connection`: First-create INFO names process-wide stream/metrics ownership; session-owned mismatch is WARN (reclaim-key), not `ignored` INFO; `AdoptTransport` last-wins stays INFO.

## Impact

- `pkg/lapi/session.go` (`SessionKey`, `OpenStream` / `OpenLive`)
- `pkg/lapi/client.go` (store in `create()`, Close hook, holder-name set, subscribe WARN, first-create INFO)
- `pkg/lapi/decisionstore.go` (stop sibling `OpenDecisionStore` on the constructor ctx)
- `pkg/lapi/zzz_session_test.go` and `pkg/lapi/zzz_decisionstore_test.go` (invert Redis-isolation and silent-mismatch; store-as-child side effects)
- `README.md` shared-session Note
- Usage packets `core_plugin_lapi_reclaim-key`, `core_plugin_middleware`, `core_plugin_decisionstore`, `core_plugin_lapi_connection` go stale until implement / devdocsimpact
- No AppSec, no live/none Key invert, no Peek restore, no two-process reclaim, no Redis key migration
