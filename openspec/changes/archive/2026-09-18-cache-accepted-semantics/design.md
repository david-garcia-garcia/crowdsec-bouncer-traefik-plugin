## Context

See `proposal.md` Why. Dest already implements the rejected-#38 tradeoffs (`pkg/cache/cache.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`). Specs name client pointers, prefix, and opaque payloads, not replica-lag reads, void Set, EX-as-given, or the stream vs live TTL split. Official Redis: `EX` must be a positive integer (`knowledge/research/ext_redis_commands_set-ex-zero/`); replication is async and this plugin does not send `WAIT` (`knowledge/research/ext_redis_replication_replica-lag/`). Vendor SimpleRedis still sends `SET EX <n>` as given. Memory `Heap.Set` no-ops when `ttl==0`.

FindSpecHost (Search: `openspec/specs/map.md` families `core_cache_redis` / `core_cache_client`; leaves `utilities-client`, `decision-store`, `isolated-store`; also `core_plugin_lapi_stream-apply`, `core_plugin_lapi_connection`):

```
verdicts:
  - { deltaId: replica-lag-reads, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store, core_cache_client_isolated-store] }
  - { deltaId: void-set-delete, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store] }
  - { deltaId: ex-as-given, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: high, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store] }
  - { deltaId: stream-vs-live-ttl, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: medium, candidates: [core_cache_client_decision-store, core_plugin_lapi_stream-apply, core_plugin_lapi_connection, core_cache_redis_utilities-client, core_cache_client_isolated-store] }
```

`utilities-client` already owns `nextReader` pointers, GET/SET/DEL, and “SimpleRedis Set remains SET EX only”. Replica-lag, void Set, and EX-as-given are one–three-requirement additions to that leaf. Stream vs live TTL is store-write policy (LAPI → DecisionStore), not Redis-client routing; `decision-store` owns those writes. `isolated-store` stays isolation-only. `stream-apply` owns deleted-before-new order, not TTL. `connection` owns who supplies live TTL, not `liveCacheTTL` substitution vs stream `Seconds()`.

## Goals / Non-Goals

**Goals:**

- Persist dest behavior as SHALL/MUST NOT + scenarios on the two folded leaves.
- One-liner comments at `nextReader`, `get`, `set`, and stream `int64(duration.Seconds())`.
- Leave Redis/memory runtime, signatures, and tests that assert dest policy unchanged.

**Non-Goals:**

- README lag/stale-read sentence (explore: knob already names replica-only reads and outage fail-closed).
- Devdocs gotchas (ticket defers to `devdocsimpact`).
- A new spec family or a fold into `core_cache_client_isolated-store`.
- Writer-on-recent-key, Set/Delete error return, EX clamp, aligning memory with Redis, changing `liveCacheTTL`, captcha cache grace, SimpleRedis fork.

## Decisions

1. **Fold, do not create a leaf.** Three Redis-client deltas → `core_cache_redis_utilities-client`. Stream vs live TTL → `core_cache_client_decision-store`. Alternative: new `core_cache_client_*` leaf — rejected (small adjustment; ticket said fold unless FindSpecHost says `new`).
2. **Comments only in product Go.** Wording: `nextReader` — readers empty → writer, else replica only; `get` — miss/replica error is not retried on the writer; `set` — Redis error is logged, Set is void; stream `Seconds()` — sub-second becomes `0`, no clamp. Alternative: skip comments — rejected; explore assumed a one-liner earns its keep at those sites.
3. **No README sentence.** Explore resolved the knob does not claim last-write visibility.
4. **No new runtime-policy tests.** Existing GET/SET/miss tests stay. Do not add a test that asserts replica-lag, void Set, EX `0`, or stream `Seconds()` truncation as new policy.
5. **Memory vs Redis stay split.** Redis sends `EX` as given (host may reject `0`). Memory `Heap.Set` no-ops `ttl==0`. Do not align them.

## Risks / Trade-offs

- [A later hunt re-opens read-your-writes or fail-closed Set] → Specs now MUST NOT those paths; comments mark the sites.
- [Official Redis rejects `SET EX 0` while we still send it] → Accepted; vendor always sends `EX`; stream sub-second durations become `0`. Persist, do not clamp.
- [Replica Get can miss a just-completed writer Set] → Accepted; no `WAIT`, no writer retry. README already names replica-only reads and outage fail-closed.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert of comments and spec deltas.

## Open Questions

None — ticket and `explore.md` decisions stand. Propose resolved FindSpecHost ids and kept the four one-liners.
