# Requirement
IssueKey: 2026-09-17-shared-decision-store

## Problem
Every `lapi.Client` owns its own `cache.Client`. Memory backends are isolated by construction, so two Client incarnations on different reclaim keys keep two decision maps and two `updated` leases. The stream lease is a Get-then-Set, so two pollers can both take the same tick. The live reclaim-key spec also omits `RedisCacheReadHosts` and does not explain why `decisionScopeHeaders` is hashed for stream/alone but not for live/none.

## Current (code)
- `pkg/lapi/client.go` `New` allocates `&cache.Client{}` and calls `cacheClient.New(...)` per Client.
- `pkg/cache/cache.go` `Client.New`: "memory clients ignore it and each own a map"; Redis uses `prefixed()`; memory builds `&localCache{store: ttl_map.New()}`.
- `pkg/cache/cache.go` `Client.Close`: nil-safe, then `c.cache.close()`. `localCache.close` is a no-op. `redisCache.close` calls `SimpleRedis.Close` on writer and readers. Vendored `simpleredis.go` `Close` is CAS and "Safe to call more than once". `cache.Client.Close` comment already says the same. Found: safe to call more than once; it does not nil `c.cache`, so a second call re-enters `close()` and relies on SimpleRedis idempotency.
- `pkg/lapi/client_stream.go` `handleStreamCache`: `Get(cacheTimeoutKey)` (`"updated"`); on miss, `Set(..., leaseDuration)` with `leaseDuration = updateInterval - 1` floored to 1. Not atomic.
- Vendored SimpleRedis exposes `Eval` (`vendor/.../simpleredis/commands_eval.go`). `pkg/cache` has no Eval/SetNX wrapper. In-tree callers of `Eval` are SimpleRedis `MSetEX` fallback only.
- `pkg/lapi/session.go` `streamSettings` includes `RedisCacheReadHosts` and `DecisionScopeHeaders`.
- `pkg/lapi/identity.go` `identity` includes `RedisCacheReadHosts` and does **not** include `decisionScopeHeaders`.
- `pkg/lapi/client_decisions.go` `streamQuery` appends `&scopes=` from `c.decisionScopeHeaders`; `storeStreamDecision` filters header scopes against that map.
- `pkg/lapi/client_live.go` `LiveLookup(remoteIP, scopes, defaultDecisionSeconds)` never reads `c.decisionScopeHeaders`. `pkg/bouncer/bouncer.go` builds per-request scopes from the Bouncer map.
- `openspec/specs/core_plugin_lapi_reclaim-key/spec.md` lists Redis host/auth/db/enabled and `decisionScopeHeaders` in the settings hash; it does not name `RedisCacheReadHosts`; it does not state the live/none header-scope asymmetry.
- `pkg/lapi/client.go` stores `transport` / `rangeMembership` in `atomic.Value` with a Yaegi v0.16 comment. Write-once scalars (`updateInterval`, `decisionScopeHeaders`, …) are read without `mu`.
- `pkg/reclaim/default.go` still has `Peek` / `PeekLivePrefix`. Debt `knowledge/debt/2026-09-17-shared-decision-store.md` is open. Sibling `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` is a later ticket.

## Desired
1. Decision store is its own reclaim entry, keyed by CrowdSec cursor identity plus store parameters, so routers share remediations without sharing a LAPI poller. Dispose via `cache.Client.Close()` (idempotent as found).
2. Stream lease is one atomic acquire: Redis `EVAL` (vendored SimpleRedis) plus a correct in-memory fallback. Do not use `atomic.Pointer[T]`. Do not turn write-once Client scalars into mutable fields.
3. Same change: spec names `RedisCacheReadHosts` in the hashed snapshot; spec explains why `decisionScopeHeaders` is in stream/alone settings and not in live/none `identity` (stream-only readers; live passes scopes per call). Code reading matches the ticket — no disagreement.
4. Implement closes this ticket’s debt file and records it on this run’s `issues.md` / card. Leave the cursor-only debt file in place.

## Affected
- `pkg/cache/`, `pkg/lapi/` (not `client_metrics.go` / `MetricsReporter`), `pkg/reclaim/` only as needed to reclaim the store
- `openspec/specs/core_plugin_lapi_reclaim-key/spec.md`
- `knowledge/debt/2026-09-17-shared-decision-store.md` (delete when landed)
- `knowledge/devdocs/core_cache_client.md` (isolated-cache language will go stale)

## Out of scope
- Delete `Peek`, `PeekLivePrefix`, or `View` from `pkg/reclaim/`
- Change `scopes=` from first-wins to a union of live routers
- Replace `pkg/reclaim` with traefik-middleware-utilities, or diverge the copy beyond what the shared store needs
- Rework session prefix or settings-hash membership beyond the shared store
- `pkg/appsec/`, `pkg/captcha/`, `pkg/lapi/client_metrics.go` / `MetricsReporter`
- `knowledge/debt/2026-09-17-cursor-only-reclaim-key.md` (still open; later ticket)
- Other runs under `devstate/2026/09/`

## Unknowns
- Exact reclaim-key fields for the DecisionStore (ticket: cursor identity plus store parameters; not designed here).
- Memory-backend atomic-acquire algorithm (mutex vs compare-and-set on the TTL map).
- Whether `pkg/cache.Client` grows an Eval/SetNX method or the lease lives behind a new store type.

## Tensions
- Spec text already lists Redis host/auth/db/enabled; code also hashes `RedisCacheReadHosts`. Ticket asks to name that field — not a code/spec bug, a naming gap.
- `knowledge/research/ext_traefik-middleware-utilities_packages/notes.md` still says this plugin’s cache does not need EVAL; that note will be stale after this change.
- No `RETHINK` comments. No disagreement with the two spec-gap facts.
