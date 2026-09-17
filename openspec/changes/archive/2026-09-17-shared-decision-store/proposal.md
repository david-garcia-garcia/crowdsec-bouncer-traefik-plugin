## Why

On DestBranch every `lapi.Client` owns its own `cache.Client`, so two Client incarnations (different intervals or live vs stream snapshots) keep two decision maps and two `updated` leases. The stream lease is Get-then-Set, so two pollers on one store can both fetch. Routers cannot share remediations without sharing a LAPI poller.

## What Changes

- Reclaim a DecisionStore (owns one `cache.Client`) keyed by CrowdSec cursor identity plus Redis store parameters. Two Clients on different Client reclaim keys Open the same store and share remediations. Dispose via `cache.Client.Close()` on the store’s reclaim Close hook only.
- Stream lease is one atomic acquire: Redis `EVAL` (vendored SimpleRedis) plus a mutex+Get/Set memory fallback. Floor TTL stays 1s. Do not use `atomic.Pointer[T]`. Do not turn write-once Client scalars into mutable fields.
- Cache prefix is `SessionHex` for every mode on that store. Live no longer uses `IdentityHex` as the prefix.
- `lapi.Client.Close` / `Sleep` stop tickers and HTTP only; they MUST NOT `Close` the shared store.
- Spec names `RedisCacheReadHosts` in the Client hashed snapshot (code already hashes it). Spec explains why `decisionScopeHeaders` is in stream/alone settings and not in live/none `identity`.
- Rename live leaf `core_cache_client_isolated-store` → `core_cache_client_decision-store` (Removed unit: isolation is by store key, not per Client).
- Implement deletes `knowledge/debt/2026-09-17-shared-decision-store.md`. Leave `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`. Do not delete Peek / PeekLivePrefix / View.
- Not **BREAKING** for operators. Public Traefik config keys stay.

## Capabilities

### New Capabilities

- `core_cache_client_decision-store`: One DecisionStore reclaim value owns the cache map; isolation is by store key (cursor + Redis params); prefix is `SessionHex`; Client Close does not dispose the store.

### Modified Capabilities

- `core_cache_client_isolated-store`: REMOVED — per-Client isolated map is the deleted unit. Remaining SHALLs (opaque payloads, isolation across different store keys) live on `core_cache_client_decision-store`.
- `core_plugin_lapi_stream-lease`: Lease acquire is atomic (Eval or memory mutex), not Get-then-Set. 1s floor stays.
- `core_plugin_lapi_reclaim-key`: Name `RedisCacheReadHosts` in the hashed snapshot. Explain `decisionScopeHeaders` stream/alone vs live/none.
- `core_cache_redis_utilities-client`: `cache.Client` grows a narrow acquire that reaches SimpleRedis `Eval` (writer + prefix) or the memory mutex. Poller logic stays off `cache.Client`.

## Impact

- `pkg/cache/` (narrow acquire / Eval; memory mutex)
- `pkg/lapi/` except `client_metrics.go` / `MetricsReporter` (DecisionStore Open, `Cache()`, Client Close/Sleep, `CachePrefix`, `handleStreamCache`)
- `pkg/reclaim/` only as needed to reclaim the store (`OpenWithHooks` + Close hook). Do not delete Peek APIs. Do not import utilities `reclaim`.
- `openspec/specs/core_cache_client_isolated-store/` (removed after archive sync)
- `openspec/specs/core_cache_client_decision-store/` (added)
- `knowledge/devdocs/core_cache_client.md` (Language + usage remap at implement)
- `knowledge/research/ext_traefik-middleware-utilities_packages/notes.md` (EVAL sentence when Eval lands)
- `knowledge/debt/2026-09-17-shared-decision-store.md` (delete on implement)
- `core_plugin_lapi_reclaim-key` usage packet (name `RedisCacheReadHosts`)
- No `pkg/appsec/`, no MetricsReporter, no first-wins `scopes=` union, no `core_plugin_reclaim` packet
