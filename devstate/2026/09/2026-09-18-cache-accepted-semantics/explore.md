# Explore

## Concepts

This ticket is document-only. Closed #38 asked for three runtime changes (read-your-writes, duration<=0 aligned no-op, Set/Delete errors for fail-closed stream/captcha). The owner rejected all three. Dest has no spec, comment, or README sentence that locks the current tradeoffs.

```
  stream/live write                         request read
        │                                        │
        ▼                                        ▼
  cache.Client.Set (void)              cache.Client.Get / GetMany
        │                                        │
        ▼                                        ▼
  redisCache.set ──► writer            nextReader()
                                         │
                    readers empty ───────┴──► writer
                    readers set ────────────► round-robin read host
                                              miss / replica error
                                              is not retried on writer
```

Grounded current behavior:

- `nextReader` returns the writer when `readers` is empty; otherwise a read-host pointer (`pkg/cache/cache.go`).
- `get` / `getMany` call `nextReader` only. No writer retry. No local written-key set.
- `set` / `delete` use the writer, log Redis errors, and return. `Client.Set` / `Delete` and `cacheInterface` are void.
- Stream apply passes `int64(duration.Seconds())` into `storeStreamDecision` → `cache.Set`. Sub-second CrowdSec durations become `0`. No stream TTL clamp (`pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`).
- `liveCacheTTL` substitutes `defaultDecisionSeconds` when `durationSecond<=0`. Live/none writes use that helper (`pkg/lapi/client_decisions.go`, `pkg/lapi/client_live.go`).
- Utilities SimpleRedis `Set` always sends `SET EX <n>` including `0` (`vendor/.../simpleredis/commands.go`).
- Memory `Heap.Set` no-ops when `ttl==0` (`vendor/github.com/leprosus/golang-ttl-map/map.go`). Redis and memory stay unaligned.
- Stream/live Set callers ignore write success. Captcha grace is the HMAC cookie (`pkg/captcha/gate.go`), not a cache key.

OpenSpec `list --json` has no active change. Existing cache specs:

- `core_cache_redis_utilities-client` — vendored client, pointer `nextReader`, timeouts, Close, miss/unreachable, Eval acquire. Does not state replica-lag reads, void Set, or EX-as-given.
- `core_cache_client_decision-store` — reclaim store, cursor+Redis key, SessionHex prefix, opaque payloads, Client Close does not dispose the store.
- `core_cache_client_isolated-store` — Purpose only (session isolation). No requirements body.

Devdocs Consume: root `knowledge/devdocs/index.md` has no `priority: always` packets. Opened `index_core_cache.md`, then `core_cache_redis.md` and `core_cache_client.md`. Those packets are enough to construct and call the cache. They do not lock replica-lag, void Set, or EX-as-given. Ticket Desired defers gotchas to later `devdocsimpact`. No Language write: no new unambiguous term was missing; Redis “replica lag” / Go “void Set” stay parked below if later phases need names.

Research Consume: root `knowledge/research/index.md` has no `priority: always`. Opened `index_ext_redis.md`, `index_ext_simpleredis.md`, `index_ext_traefik-middleware-utilities.md`, `index_ext_dragonfly.md`. No SET-EX or replica-lag leaf existed. Wrote `ext_redis_commands_set-ex-zero/` and `ext_redis_replication_replica-lag/` (Task tool not available; wrote on this thread). Official SET: `EX seconds` is a positive integer. Official replication is async by default; this plugin does not send `WAIT`.

This work does not reconstruct client address, user, tenant, Host, or trust hop. Cache keys stay on DecisionStore / `GetRemoteIP` / `SessionHex` already named on `core_cache_client_decision-store`. It is not a Traefik `New` / shared-ticker change; no new `sync.Once` or package global.

Sibling `2026-09-18-cache-ttl-guard-and-read-your-writes` and closed #38 stay out of scope.

## Decisions

- Persist current behavior as the contract. No Redis/memory runtime change. No signature change. No test that asserts a new runtime policy.
- Fold SHALL/MUST NOT + scenarios into existing cache specs. Propose picks ids via FindSpecHost. Likely host for routing / void Set / EX-as-given: `core_cache_redis_utilities-client`. Stream vs live TTL split may fold on `core_cache_client_decision-store` if FindSpecHost says that leaf owns store writes; do not invent a new family unless the librarian says `new`. `core_cache_client_isolated-store` stays isolation-only unless FindSpecHost folds a delta there.
- Short comments at `nextReader` / `get` / `set` and stream `int64(duration.Seconds())` only if a one-liner earns its keep. No behavior change.
- README `RedisCacheReadHosts`: **no lag/stale-read sentence**. The knob already names replica-only reads (round-robin), empty-list fallback to the writer, and replica-outage fail-closed with no primary retry. That text does not claim the last write is visible. Live-mode “Traefik replicas reuse LAPI answers” is shared-cache among Traefik processes, not Redis replica consistency.
- Devdocs usage/Language: write nothing this phase (Consume: enough to call; ticket defers gotchas).
- Official Redis `SET EX 0` is invalid (`EX` must be a positive integer; `SETEX` errors on invalid seconds). Vendor still sends `EX` as given. Persist that split; do not align memory `ttl==0` no-op with Redis.
- Do not reuse closed PR #38 or branch `2026-09-18-cache-ttl-guard-and-read-your-writes`.

## Open questions

- Q: Official Redis SET EX 0 rejection — is the owner-stated fact true?
  Decision: resolved — official SET documents EX seconds as a positive integer; SETEX returns an error when seconds is invalid. Persist EX-as-given plus memory ttl==0 no-op; do not align them. See `knowledge/research/ext_redis_commands_set-ex-zero/`.
  By: explore

- Q: Does README RedisCacheReadHosts still imply reads are consistent with the last write?
  Decision: resolved — no. Knob already names replica-only reads and outage fail-closed. Do not add a lag/stale-read sentence.
  By: explore

- Q: Who already owns client address / session identity for cache keys?
  Decision: resolved — this change does not reconstruct identity. Reuse DecisionStore / `pkg/ip.GetRemoteIP` / `SessionHex` already named on `core_cache_client_decision-store`.
  By: explore

- Q: Exact spec ids after FindSpecHost?
  Decision: assumed — propose folds into existing cache specs via FindSpecHost; try `core_cache_redis_utilities-client` for routing / void Set / EX-as-given, and `core_cache_client_decision-store` only if that leaf owns stream vs live TTL writes. Do not create a new family unless FindSpecHost says new.
  By: explore

- Q: One-liner comments at nextReader/get/set and stream Seconds()?
  Decision: assumed — yes, only if a one-liner earns its keep at those sites; no behavior change. Propose/implement choose wording or skip.
  By: explore

- Q: Devdocs gotchas for replica lag, void Set, or EX-as-given?
  Decision: assumed — not this phase. Ticket defers to later `devdocsimpact`. Existing cache packets stay as-is.
  By: explore

- Q: Does Dragonfly accept SET EX 0 unlike Redis?
  Decision: assumed — out of scope to align or special-case. Contract is we send EX as given; the host may reject. Do not add a Dragonfly runtime branch.
  By: explore
