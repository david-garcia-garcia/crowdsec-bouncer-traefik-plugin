## Context

See proposal.md Why. DestBranch: `lapi.New` allocates `&cache.Client{}` per Client (`pkg/lapi/client.go`); `handleStreamCache` is Get-then-Set of `updated` (`pkg/lapi/client_stream.go`); `CachePrefix` is `SessionHex` for stream/alone and `IdentityHex` for live/none (`pkg/lapi/session.go`). Vendored SimpleRedis already has `Eval` (`vendor/.../simpleredis/commands_eval.go`). Dragonfly EVAL/EVALSHA is fully supported (`ext_dragonfly_scripting_eval`). CrowdSec cursor owner is the LAPI bouncer row; this process reuses `SessionHex` / `streamSession` (`ext_crowdsec_lapi_stream-cursor`). Visitor address owner is `pkg/ip.GetRemoteIP`. Store location owner is the Redis connection fields on config. Yaegi: `OpenWithHooks` + type assert, no `atomic.Pointer[T]`, no `OpenTyped` cross-package generic.

## Goals / Non-Goals

**Goals:**

- One DecisionStore per cursor + Redis params, reclaimed on Traefik `New` ctx
- Atomic `updated` acquire (Eval + memory mutex)
- SessionHex prefix for every mode on that store
- Client Close/Sleep do not dispose the shared cache

**Non-Goals:**

- Union of `scopes=` across live routers
- Delete Peek / PeekLivePrefix / View
- Import utilities `reclaim`
- `core_plugin_reclaim` usage packet
- MetricsReporter / AppSec / cursor-only debt file

## Decisions

1. **DecisionStore type lives in `pkg/lapi`** (file `decisionstore.go`). Clients already own `SessionHex` and Open. `cache.Client` stays the map/pool. Alternative: `pkg/cache` store type — rejected; reclaim key uses lapi cursor identity, and `cache` would import session hashing.

2. **Reclaim table key** = `decisionstore:` + `SessionHex(cfg)` + `:` + hash of Redis enabled/host/readHosts/password/database. Same hasher as `hashJSON`. Alternative: reuse `SessionKey` — rejected; that includes poller knobs and would block sharing across interval mismatches.

3. **Open path**: `OpenStream` / `OpenLive` Open the store with the same `ctx` before or inside `New`. `Client` holds `*DecisionStore`. `Cache()` returns `store.Cache()`. Alternative: package `var` map — rejected (`std_go_reclaim`). Alternative: `sync.Once` — rejected.

4. **Hooks**: store Close = `cache.Client.Close()` (already idempotent). No Sleep/Wake. Client hooks stay Sleep/Wake/Close but Close no longer calls `cache.Client.Close()`. Alternative: Client Close still closes cache when unique holder — rejected; holder count is the reclaim table’s job.

5. **Lease API**: DecisionStore method calls `cache.Client` acquire. Redis Lua: SET EX if EXISTS == 0 on the prefixed `updated` key; return 1/0. Digest via `simpleredis.ScriptSHA1Hex` at init. Memory: mutex on the memory path of `cache.Client`. Alternative: SetNX wrapper — rejected (ticket wants EVAL; SimpleRedis Set is SET EX only). Alternative: `atomic.Pointer[T]` — forbidden.

6. **Prefix**: `SessionHex` for every mode. `CachePrefix` becomes `SessionHex` (or DecisionStore sets it). Live `IdentityHex` remains the Client reclaim key suffix only. Alternative: keep live `IdentityHex` prefix — rejected; intervals would isolate live from other live Clients that should share.

7. **Identity**: do not add a second cursor or visitor calculation. Reuse `sessionFrom` / `SessionHex` and `pkg/ip.GetRemoteIP`.

8. **Removed unit**: rename `core_cache_client_isolated-store` → `core_cache_client_decision-store`. Update `core_cache_client.md` Language/usage at implement. Update utilities research EVAL sentence when Eval lands.

## Risks / Trade-offs

- [Two stream pollers still warn-and-wire to one Client] → Shared store still helps live/none interval splits and any future Client-key split that keeps the same store key. Do not union `scopes=`.
- [Mode in `streamSession` isolates stream from live stores] → Intended; cursor includes mode. Do not drop mode from `SessionHex`.
- [Lua on Dragonfly vs Redis] → e2e cache is Dragonfly; EVAL/EVALSHA fully supported. Eval hop timeouts stay one-command-each (`Eval` contract).
- [Tests assign `cacheClient` on Client literals] → Point them at a DecisionStore or a test helper; do not keep a second production closer.

## Migration Plan

- In-process: new Open keys; old isolated maps die with their Client grace.
- Redis: key prefix for live/none changes from `IdentityHex` to `SessionHex`. No migration of existing keys (same rule as the isolated-store cut). Operators may see a one-interval miss until the stream fills the new prefix.
- Rollback: revert the change; live keys return to `IdentityHex`.
