# Requirement
IssueKey: 2026-09-18-cache-accepted-semantics

## Problem
Closed #38 asked for Redis read-your-writes, duration<=0 no-op aligned on memory and Redis, and Set/Delete errors for fail-closed stream/captcha. Owner rejected all three. Dest has no spec, comment, or README sentence that locks the current tradeoffs, so a later defect hunt can re-open them.

## Current (code)
- `nextReader` returns the writer when `readers` is empty; otherwise round-robin over read-host pointers. `pkg/cache/cache.go`
- `get` / `getMany` call `nextReader` only. Miss or replica error is not retried on the writer. There is no local set of recently written keys. `pkg/cache/cache.go`
- `set` / `delete` use the writer, log Redis errors, and return. `Client.Set` / `Delete` and `cacheInterface` are void. `pkg/cache/cache.go`
- Stream apply passes `int64(duration.Seconds())` into `storeStreamDecision` → `cache.Set`. Sub-second CrowdSec durations become 0. No stream TTL clamp. `pkg/lapi/client_stream.go` `pkg/lapi/client_decisions.go`
- `liveCacheTTL` substitutes `defaultDecisionSeconds` when `durationSecond<=0`. Live/none writes use that helper. `pkg/lapi/client_decisions.go` `pkg/lapi/client_live.go`
- Utilities SimpleRedis `Set` always sends `SET EX <n>` with the duration as given (including 0). `vendor/github.com/david-garcia-garcia/traefik-middleware-utilities/simpleredis/commands.go`
- Memory `Heap.Set` no-ops when `ttl==0` (does not store). Redis and memory are not aligned. `vendor/github.com/leprosus/golang-ttl-map/map.go` `pkg/cache/cache.go`
- Stream/live Set callers ignore write success. Captcha grace is the HMAC cookie, not a cache key. `pkg/lapi/client_decisions.go` `pkg/captcha/gate.go`
- Cache specs cover client pointers, prefix, and opaque payloads. They do not state replica-lag reads, void Set, or EX-as-given. `openspec/specs/core_cache_redis_utilities-client/spec.md` `openspec/specs/core_cache_client_decision-store/spec.md` `openspec/specs/core_cache_client_isolated-store/spec.md`
- README `RedisCacheReadHosts` names round-robin, empty-list fallback to the writer, and replica-outage fail-closed. It does not name replica lag after a primary Set. `README.md`

## Desired
- Persist current behavior as the contract. No Redis/memory runtime change. No signature change. No test that asserts new runtime policy.
- Fold SHALL/MUST NOT + scenarios into existing cache specs (likely `core_cache_redis_utilities-client` and/or `core_cache_client_isolated-store` / DecisionStore). Propose picks ids via FindSpecHost.
- Short comments at `nextReader`/`get`/`set` and stream `int64(duration.Seconds())` if a one-liner earns its keep.
- Devdocs gotchas only if later `devdocsimpact` says so.
- README lag/stale-read sentence only if explore finds the knob still implies read-your-writes.

## Affected
- `openspec/specs/core_cache_redis_utilities-client/` (likely)
- `openspec/specs/core_cache_client_decision-store/` (likely)
- `openspec/specs/core_cache_client_isolated-store/` (possible)
- `pkg/cache/cache.go` (comments only)
- `pkg/lapi/client_stream.go` (comment only, if kept)
- `README.md` (only if explore finds implied consistency)
- `knowledge/devdocs/core_cache_redis.md` / `core_cache_client.md` (only if `devdocsimpact` says so)

## Out of scope
- Writer-on-recent-key / retry Get on writer on miss / local written-key set
- Set/Delete error return or fail-closed stream/captcha on write miss
- Stream TTL clamp or making `localCache` match Redis
- Changing `liveCacheTTL`
- Captcha cache grace
- SimpleRedis fork
- backendbackoff, HTTP timeouts, captcha JSON, module rename
- Reuse of closed PR #38 or branch `2026-09-06-cache-redis-semantics`

## Unknowns
- Official Redis `SET EX 0` rejection is owner-stated; `knowledge/research/` has no SET-EX leaf (vendor always sends `EX`).
- Whether README fallback/outage text still reads as “last write is visible” — explore decides.
- Exact spec ids after FindSpecHost (propose).

## Tensions
- Closed #38 wanted the opposite of all three owner decisions.
- Memory `ttl==0` is a silent no-op; Redis sends `EX 0` and logs the error. Owner accepts both; do not align them.
- Live TTL already substitutes a default; stream TTL does not. Owner wants that split kept.
- Sibling branch `2026-09-18-cache-ttl-guard-and-read-your-writes` is the rejected approach. Do not reuse it or #38.
