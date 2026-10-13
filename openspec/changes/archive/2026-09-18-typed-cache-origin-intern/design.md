## Context

See `proposal.md` Why. Dest `cacheInterface` is string-only (`pkg/cache/cache.go`). Leftover helpers live in `pkg/cache/remediation.go`. `DecisionStore` owns only `*cache.Client` (`pkg/lapi/decisionstore.go`). Stream write is `RemediationWithOrigin` then `Set` plus `rememberActiveDecision` with an origin string (`pkg/lapi/client_decisions.go`, `pkg/lapi/client_stream.go`, `pkg/lapi/client_metrics.go`). Lookup is `GetMany` strings (`pkg/decisionscope/lookup.go`). Vendored `ttl_map.Heap.Set` takes `interface{}`. SimpleRedis has `Set`/`Get` `[]byte` and no Int helper. Client address owner is `pkg/ip.GetRemoteIP` (`explore.md`).

FindSpecHost:

```
verdicts:
  - { deltaId: typed-bag-setint, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store, core_cache_client_isolated-store] }
  - { deltaId: origin-intern, fold|new: fold, spec-id: core_cache_client_decision-store, confidence: high, candidates: [core_cache_client_decision-store] }
  - { deltaId: leftover-and-lookup, fold|new: fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes] }
  - { deltaId: compact-slots, fold|new: fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics] }
  - { deltaId: redis-int, fold|new: fold, spec-id: core_cache_redis_utilities-client, confidence: medium, candidates: [core_cache_redis_utilities-client, core_cache_client_decision-store] }
```

Search: `core_cache_client_decision-store` already owns “opaque strings” and the DecisionStore reclaim value. Typed bag plus intern is a 1–3 requirement adjustment of that leaf, not a new family. `core_plugin_decisions_scopes` already owns leftover origin suffix and range-index lines. `core_plugin_lapi_usage-metrics` already owns `activeDecisionSlots`. Redis Int encoding is a small fold onto `core_cache_redis_utilities-client`. Do not use the change kebab as a 4th part.

## Goals / Non-Goals

**Goals:**

- Memory stream/alone Ip and header values are a packed word when intern succeeds.
- Cache stays a typed bag with no remediation codec.
- Leftover string path and range-index encoding stay in `decisionscope`.
- Allow-path `GetInt` has no intern lock. Origin name resolves on drop.
- Slot map stays; values are `originID` + family.

**Non-Goals:**

- Redis intern table.
- Replacing `ttl_map`.
- Dropping `activeDecisionSlots`.
- Extracting stream/live/metrics packages.
- Reopening PR 99 or copying `pack-decision-origin`.
- A 400K-IP RSS probe.

## Decisions

1. **`GetInt` miss is the leftover signal.** Memory type-asserts `uint32`; Redis parses decimal ASCII. Any other stored value is `CacheMiss`; caller `Get`s the string. Alternative: cache-owned Packed/Leftover types — rejected (wrong domain; closed PR 99).
2. **Leftover helpers move to `decisionscope`.** Same owner as letters and range-index. Delete `pkg/cache/remediation.go`. Alternative: a new `pkg/remediation` — rejected (consume before produce; `decisionscope` already owns the letters).
3. **Intern is a DecisionStore field.** Append-only under a write mutex; `OriginName` lock-free (atomic snapshot or copy-on-write slice). Not a package var. Thin Client forwards only if tests cannot hold the store. Alternative: intern on `cache.Client` — rejected (ticket; cache must not know origin).
4. **Pack word `uint32(kind[0]) | uint32(id)<<8`.** Overflow does not wrap; leftover `Set`.
5. **Packed range-index line is letter + decimal id.** Leftover stays letter + U+001F + origin name. Blob uses `Set`. Alternative: `\x1e` range encoding — rejected (PR 99; cache/range separator in the wrong domain).
6. **Redis writers keep leftover strings.** `SetInt`/`GetInt` still exist (decimal ASCII via existing `Set`/`Get` `[]byte`) for symmetry and tests. Alternative: Redis intern — out of scope.
7. **Lookup stays on `*cache.Client` plus membership.** It returns kind plus leftover origin or packed id. Bouncer/`IncDropped` call `DecisionStore.OriginName` only when remediating. Alternative: lookup takes the store and resolves on every hit — rejected (allow-path must not take a second lock).
8. **`activeDecisionSlots` values become `{originID, family}`.** Gauge POST still emits origin names. Keep the map for per-slot forget.

## Risks / Trade-offs

- [A Redis replica cannot resolve packed origin ids] → Redis writers keep leftover strings; intern is memory-store only.
- [Tests that construct a Client without a DecisionStore cannot intern] → keep leftover `Set` on that path; thin forwards only when a store exists.
- [Packed range line `t12` vs leftover `t\x1fcrowdsec`] → first letter is the kind; leftover is U+001F; packed id is decimal digits only.

## Migration Plan

No operator JSON/YAML key change. Memory keys rewrite on the next stream apply. Redis leftover strings stay valid. Rollback is revert.

## Open Questions

None. Proceed policies live on `devstate/explore.md`.
