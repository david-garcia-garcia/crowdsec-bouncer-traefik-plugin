# Explore

## Concepts

**DecisionStore** is a reclaim value that owns one `cache.Client` (memory TTL map or Redis-protocol pool). It is not a LAPI poller and not a Bouncer. Two `lapi.Client` incarnations on different Client reclaim keys can Open the same store and share remediations. Dispose is `cache.Client.Close()` via the store’s reclaim Close hook.

**CrowdSec cursor identity** is the LAPI bouncer row CrowdSec selects (SHA-512 of the API key plus the outbound IP LAPI sees). This process already keys that row as `streamSession` / `SessionHex` (mode, LAPI scheme/host/path, lapiKey, CAPI machine+password). It is not the visitor address. Visitor IP stays `pkg/ip.GetRemoteIP`.

**Store parameters** are where the map lives: Redis on/off, write host, read hosts, password, database. The Redis key prefix is derived from cursor identity (`SessionHex`), not from live `IdentityHex` (intervals would split stream and live).

**Stream lease** is cache key `updated`. Today `handleStreamCache` is Get-then-Set (`pkg/lapi/client_stream.go`). Two pollers on one store can both miss and both fetch. Redis acquire is one `SimpleRedis.Eval` (`EVALSHA` then `EVAL` on NOSCRIPT). Memory acquire is a mutex around miss+Set: vendored `ttl_map.Heap` Get and Set take separate locks; there is no CAS. Floor TTL stays 1s (`core_plugin_lapi_stream-lease`).

**Reclaim holder** is Traefik `New` ctx. Sister geoblock (`plugin.go` `bindPlugin`) and modsecurity (`modsecurity.go` `bindPlugin`) call `reclaim.OpenTyped` with that ctx and `Hooks{Close}`. This plugin already does the same with in-tree `pkg/reclaim` `OpenWithHooks` for `lapi.Client` and `appsec.Client` (`std_go_reclaim`, `core_plugin_middleware`). Do not add `sync.Once` or a package-level cache map. This plugin must not import utilities `reclaim` (Peek would be unreachable). Do not use `OpenTyped` as a cross-package generic instantiation (Yaegi); keep `OpenWithHooks` + type assert.

**Isolated cache** (`core_cache_client.md`, `core_cache_client_isolated-store`) is the DestBranch unit: one map per `lapi.Client`. This change removes that unit for Clients that share a store key. Propose remaps that spec/usage leaf in the same change. Range membership stays on `lapi.Client` (in-process trees); hydrate from the shared `range-index`.

```
  New(ctx) ──► OpenStream/OpenLive (Client key) ──► *lapi.Client (poller)
       │
       └──► Open DecisionStore (store key) ──► *DecisionStore ──► cache.Client
                    ▲
                    └── same ctx holder; last store holder Close()s the cache
```

## Decisions

- Open the DecisionStore with `reclaim.OpenWithHooks(ctx, storeKey, …)` using the same Traefik `New` ctx as LAPI/AppSec. Process table `Default()` / `ProcessGrace` 30s. Close hook = `cache.Client.Close()`. No Sleep/Wake (no ticker). No `sync.Once`. No package `var` map.
- Store key = cursor identity (`streamSession` fields) plus Redis store parameters (`RedisCacheEnabled`, host, read hosts, password, database). Prefix = `SessionHex` for every mode that shares this store. Exclude intervals, metrics, `updateMaxFailure`, `decisionScopeHeaders`, TLS, failure action, `StreamStartupBlock`, live-cache TTL, middleware name.
- `lapi.Client` holds the reclaimed store and exposes `Cache()` as today. `Client.Close` / `Sleep` must not `Close` a shared store; only the store’s reclaim Close hook does.
- Lease: DecisionStore method. Redis = vendored `Eval` (Dragonfly EVAL/EVALSHA fully supported: `ext_dragonfly_scripting_eval`). Memory = mutex + Get/Set of `updated`. Do not use `atomic.Pointer[T]`. Do not turn write-once Client scalars into mutable fields.
- `pkg/cache.Client` grows a narrow acquire that talks to the writer/prefix (Eval) or the memory mutex. Do not put poller logic on `cache.Client`.
- Spec `core_plugin_lapi_reclaim-key`: name `RedisCacheReadHosts` in the hashed snapshot (code already hashes it). Explain `decisionScopeHeaders` in stream/alone settings and not in live/none `identity` (stream `scopes=` is poller-owned; live passes scopes per `LiveLookup` call).
- Implement deletes `knowledge/debt/2026-09-17-shared-decision-store.md` and records it on this run’s `issues.md`. Leave `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md`. Do not delete Peek / PeekLivePrefix / View.
- Do not create a `core_plugin_reclaim` packet. `std_go_reclaim` + `core_plugin_middleware` already own New-ctx reclaim. Update `core_cache_client` usage when the store is shared. Update the utilities research sentence that says this cache does not need EVAL when Eval lands.
- First-wins `scopes=` and warn-and-wire stay on the Client reclaim key. Out of scope to union header maps.

## Open questions

- Q: What exact fields go into the DecisionStore reclaim key?
  Decision: assumed — cursor identity is `streamSession` (mode, LAPI scheme/host/path, lapiKey, CAPI machine+password). Store parameters are Redis enabled/host/readHosts/password/database. Prefix is `SessionHex` of that cursor, not a separate key field. Exclude poller knobs (`updateIntervalSeconds`, `metricsUpdateIntervalSeconds`, `updateMaxFailure`, `decisionScopeHeaders`) and dropped Client fields (TLS, failure action, `StreamStartupBlock`, live-cache TTL, middleware name).
  By: explore

- Q: What is the memory-backend atomic-acquire algorithm?
  Decision: resolved — mutex on the DecisionStore (or the memory path of `cache.Client`) around miss+Set of `updated`. Vendored `ttl_map.Heap` Get and Set are separately locked; there is no compare-and-set. Do not use `atomic.Pointer[T]`.
  By: explore

- Q: Does `pkg/cache.Client` grow Eval/SetNX, or does the lease live only on a new store type?
  Decision: assumed — new DecisionStore type holds `cache.Client` and owns the lease API. `cache.Client` grows a narrow acquire that reaches SimpleRedis `Eval` (writer + prefix) or the memory mutex. Poller/stream logic stays off `cache.Client`. SimpleRedis `Set` is SET EX only (no NX); ticket wants EVAL, not a new SetNX wrapper.
  By: explore

- Q: Who already owns identity facts this work might set (visitor address, CrowdSec cursor, store location, Host/tenant)?
  Decision: resolved — visitor address is `pkg/ip.GetRemoteIP` (`core_plugin_ip`); do not parse `RemoteAddr`. CrowdSec cursor owner is LAPI’s bouncer row (hashed key + outbound IP LAPI sees); this process reuses `SessionHex` / `streamSession`, not a reconstructed hop. Store location owner is the Redis connection fields on config. Host/tenant: none.
  By: explore

- Q: How is DecisionStore process lifetime bound when Traefik calls New per router?
  Decision: resolved — `reclaim.OpenWithHooks` on `pkg/reclaim` `Default()` with Traefik `New` ctx, same as `lapi.OpenStream` / `OpenLive` and `appsec.Open`. Sister geoblock and modsecurity bind Plugin cores the same way (`OpenTyped` + Close). Do not use `sync.Once` or package globals. Do not import utilities `reclaim`.
  By: explore

- Q: May `lapi.Client.Close` still call `cache.Client.Close` after the store is shared?
  Decision: assumed — no. Only the store’s reclaim Close hook calls `cache.Client.Close()`. Client Close/Sleep stop tickers and HTTP only. `Cache()` still returns the shared `cache.Client` for Get/Set.
  By: explore

- Q: What Redis/memory prefix do stream and live Clients use when they share a store?
  Decision: assumed — the store’s prefix is `SessionHex` (cursor identity) for every mode on that store key. Do not keep live `IdentityHex` as the prefix; intervals would isolate live from stream.
  By: explore

- Q: Does DecisionStore need Sleep/Wake hooks?
  Decision: resolved — Close only. The store has no ticker. Client Sleep already keeps cache warm. Last New-ctx holder of the store key grace-then-Close. Sisters use Close-only hooks for non-ticker cores.
  By: explore

- Q: Does `decisionScopeHeaders` belong on the DecisionStore key?
  Decision: assumed — no. It is a stream poller filter (`scopes=`), already first-wins on the Client settings hash. Live passes scopes per call. Putting it on the store key would block sharing remediations across header-map mismatches; leaving it off matches “cursor plus store parameters.”
  By: explore

- Q: Should explore/propose add a `core_plugin_reclaim` usage packet?
  Decision: assumed — no. `std_go_reclaim` and `core_plugin_middleware` already document New-ctx reclaim. A third packet would fold the same unit. Isolated-cache usage is updated when the store is shared, not replaced by a reclaim glossary.
  By: explore

- Q: When is the utilities research line “this plugin’s cache does not need EVAL” updated?
  Decision: assumed — same change that lands `Eval`, in `knowledge/research/ext_traefik-middleware-utilities_packages/notes.md`. Do not rewrite that folder in explore.
  By: explore

- Q: What happens to `core_cache_client_isolated-store` / `core_cache_client.md` when two Clients share a map?
  Decision: assumed — this change removes the isolated-per-Client unit for a shared store key. Propose remaps that spec and usage leaf in the same change (FindSpecHost removed unit). Different store keys still isolate. Do not keep a process-wide package map.
  By: explore
