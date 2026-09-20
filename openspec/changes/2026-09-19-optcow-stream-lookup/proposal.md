## Why

Stream Ip/header lookup and Redis were still specified as `pkg/cache` (`cache.Client` lease, leftover U+001F strings, `liveTick`). The apply deleted `pkg/cache` and put memory COW maps, Redis SimpleRedis, intern, Range membership, pack, and request lookup on `pkg/decisionstore.Store`. Specs must name that unit.

## What Changes

- **Rename** `core_cache_client_decision-store` → `core_plugin_decisionstore_store`: `pkg/decisionstore.Store` (engine funcs at `NewMemory`/`NewRedis`, memory COW maps, Redis SimpleRedis, intern, Range membership, pack, lookup).
- Fold remaining Redis isolation and writer/replica semantics onto that store leaf. **Remove** `core_cache_redis_utilities-client`, `core_cache_client_isolated-store`, and `core_plugin_lapi_stream-lease` (`Acquire` / `updated` dropped; pollers do not overlap; pods distinct by LAPI+IP).
- Stream apply is Store `BeginTick` / `Put` / `Delete` / `PublishTick` / `ApplyRangeBatch`. Request lookup is one Store call. Live LAPI returns `(kind, origin, error)` fields. Range blob is `cidr=kind` then origin on the next newline. Intern overflow is Warn + origin id 0. No leftover `\x1f`, no `pkg/cache`, no `liveStore` type.

## Capabilities

### New Capabilities

- `core_plugin_decisionstore_store`: `pkg/decisionstore.Store` reclaim value — engine, memory COW, Redis SimpleRedis, intern, Range, pack, lookup.

### Modified Capabilities

- `core_cache_client_decision-store`: REMOVED — remaining unit renamed to `core_plugin_decisionstore_store`.
- `core_cache_redis_utilities-client`: REMOVED — Redis engine lives on the store; Acquire dropped.
- `core_cache_client_isolated-store`: REMOVED — SessionHex prefix isolation lives on the store.
- `core_plugin_lapi_stream-lease`: REMOVED — stream lease dropped.
- `core_plugin_lapi_stream-apply`: Apply through Store tick and `ApplyRangeBatch`; no `liveTick`; no `cache.Set`; no lease.
- `core_plugin_decisions_scopes`: Letters and `PreferRemediation` stay in `decisionscope`. Persistence, pack, Range membership, lookup live in `decisionstore`. Drop leftover U+001F / `GetInt` leftover path.
- `core_plugin_middleware_bouncer`: One Store lookup for live/stream/alone memo; `LiveLookup` kind+origin fields.
- `core_plugin_lapi_reclaim-key`: DecisionStore prefix owner is `core_plugin_decisionstore_store`.
- `core_plugin_lapi_stream-single-flight`: Intra-instance poll lock only; drop lease wording.
- `core_plugin_lapi_usage-metrics`: Overflow origin is intern id 0 / empty `OriginName`, not a leftover string.
- `core_plugin_middleware_captcha-routing`: Drop `Cache().Acquire` / stream-lease wording.
- `std_go_logger_debug-attrs`: Drop `cache.Client` Get/GetMany/Set/Delete Debug scenarios.
- `build_ci_github_module-path`: Drop `pkg/cache` Yaegi import scenario.

## Impact

- `pkg/decisionstore/` Store, memory, redis, pack, range, lookup
- `pkg/lapi/` stream apply, live memo via Store `Put`, `LookupRemediation`
- `pkg/decisionscope/` letters, PreferRemediation, RequestScopeValues, StreamScopeList, Normalize*, RemediationKind
- `pkg/bouncer/` one Store lookup; LiveLookup kind+origin
- Catalog `openspec/specs/core_cache_*` leaves retire at archive; archive folders keep historical ids
- PR #118 target `master`
