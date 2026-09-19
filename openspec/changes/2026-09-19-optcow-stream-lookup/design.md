## Context

See `proposal.md` — the branch currently implements OptCOW as `DecisionStore` live map plus `Client.liveTick` apply branching and bouncer `UsesLiveSnapshot`. Explore locked the replacement: one stream store on `DecisionStore`, backend picked at open, `Client` never holds tick scratch or mode flags. Reclaim key and Traefik `New` ctx holder stay as in `core_plugin_lapi_reclaim-key` / `core_cache_client_decision-store`.

## Goals / Non-Goals

**Goals:**

- `streamStore` interface (name may vary) on `DecisionStore`: `Put`, `Delete`, `BeginTick`, `PublishTick`, `LookupRemediation` (or equivalent) for stream/alone Ip and header keys only.
- `redisStreamStore`: Put/Delete → `cache.Client` with existing stream TTL; lookup uses Get/GetInt + leftover rules as today on Redis; tick methods no-op.
- `memoryStreamStore`: one `atomic.Value` of `map[string]liveSlot{word uint32, expiresAt int64}`; tick clone → apply deleted/new → expiry sweep → single `Store`; lookup `Load` + one probe per Ip/header key; skip Range when Ip probe is ban.
- `lapi.Client`: `storeStreamDecision` / `deleteStreamDecision` always call store; `LookupStreamRemediation(remoteIP, ipAddr, scopes)` delegates to `decisionStore` stream store + `RangeMembership()`.
- Bouncer: stream/alone always `LookupStreamRemediation`; live/none unchanged (`LookupCachedRemediation` / live path).
- Intern overflow: `Table` Warn + pack kind-only (id 0); no `Leftover` on `liveSlot`; no GetMany on memory stream lookup.
- Remove: `liveTick`, `publishLiveTick`, `UsesLiveSnapshot`, `livesnapshot.go` bolt-on, bouncer mode branch.
- Benchmarks vs `origin/master` for delivery card.

**Non-Goals:**

- Patricia merge, live/none on memory map, Redis GetMany removal, Helper /32 stuffing, changing `origin/HEAD`.

## Decisions

1. **Interface location:** `streamStore` as a private interface field on `DecisionStore`, constructed in `OpenDecisionStore` when `PacksMemory()` vs Redis-backed — avoids exporting another package type and keeps reclaim ownership obvious.
   - *Alternative:* methods directly on `DecisionStore` — rejected to keep Redis/memory files separable and testable.

2. **Redis tick API:** `BeginTick`/`PublishTick` exist on the interface but are no-ops for Redis so `fetchAndApplyStreamDecisions` has one code path.
   - *Alternative:* type assert to memory-only ticker — rejected (Client would branch on store kind).

3. **Lookup owner:** `decisionscope` provides merge logic (Ip + headers + Range, ban wins) invoked from memory/redis store lookup and from `Client.LookupStreamRemediation`; live/none keep `LookupCachedRemediation`.
   - *Alternative:* duplicate merge in `pkg/lapi` — rejected (one job, one owner).

4. **Key strings:** Reuse `IPCacheKey` / `HeaderScopeKey` and bouncer `req.remoteIP` — no second IP map or re-parse (`explore` lock).

5. **Range locks:** No utilities change; immutable hydrate snapshots + vendor `RLock` on `Contains` satisfies requirement.

6. **Implement strategy:** Delete/replace bolt-on files (`livesnapshot.go`, Client fields, decisionstore live map on wrong layer if duplicated) rather than layering on branch code.

## Risks / Trade-offs

- **[Risk] Large replace diff on an already-implemented branch** → Mitigation: tasks ordered store → apply → lookup → bouncer → delete bolt-on; tests per layer.
- **[Risk] Redis and memory lookup diverge subtly** → Mitigation: shared merge helper; scenarios in `core_plugin_decisions_scopes` delta; bench both backends where cheap.
- **[Risk] Overflow without leftover loses origin name on memory** → Mitigation: explicit spec scenario; matches existing overflow metrics posture (Warn, kind-only).

## Migration Plan

- No Redis key migration; memory stops writing stream Ip/header into TTL heap — cold restart rebuilds from stream.
- Operators: none; deploy replaces in-process implementation only.

## Open Questions

None — explore open items resolved in propose (interface on `DecisionStore`, Redis no-op ticks, Client lookup entry, overflow Warn).
