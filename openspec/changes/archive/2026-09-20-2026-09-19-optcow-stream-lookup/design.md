## Context

The apply deleted `pkg/cache` and folded Redis, Range, live/none memo, pack, and membership onto `pkg/decisionstore.Store`. Live/none memo is Store `Put`/`Lookup`, not a second store type. Stream lease (`Acquire` / `updated`) is gone: in-process pollers are single-flight; distinct pods use distinct LAPI+IP rows.

## Goals / Non-Goals

**Goals:**

- Specs describe the landed Store: engine funcs bound at `NewMemory`/`NewRedis` (`memoryEngine`/`redisEngine`), not a backend interface and not `if mem` / `if red` on every method. A constructed Store always has those callbacks; methods do not nil-check `s` or the funcs. Close twice is tested on a real Redis store only. Utilities pin is `traefik-middleware-utilities` v1.0.5 (published vendor; do not re-patch `iplookup/helper.go`).
- Memory: `map[string]uint32` + `map[string]int64` (always non-nil); tick clone → apply → expiry sweep → publish. Live `Put` copy-on-write onto published maps when no tick is open.
- Redis: SimpleRedis writer + optional readers inside `pkg/decisionstore`. `nextReader` never retries the writer when readers exist. SET/DEL are void (log and return). Miss vs unreachable are `store:miss` / `store:unreachable`.
- Intern: `[]string` + `map[string]uint16`. Empty name is id 0. Overflow does not wrap: Warn, pack origin id 0 (generic empty intern name). No leftover strings on Redis.
- Encoding: memory pack word `uint32(kind[0]) | uint32(id)<<8`. Redis slot and Range payload: `KindOriginString` = kind + newline + origin (bare kind when origin empty). Range blob: `cidr=kind` then origin on the next newline line.
- Lookup: `Store.LookupRemediation` for stream/alone and live/none. Unexported `lookupHits` / `lookupKeys` in `decisionstore`. Ban on Ip skips Range membership. `HeaderScopeKey` / `IPCacheKey` live in `decisionstore`.
- `decisionscope` owns letters, `PreferRemediation`, `RequestScopeValues`, `StreamScopeList`, `Normalize*`, `RemediationKind` (first letter only).
- Live LAPI returns `(kind, origin, error)` fields; no concat-then-split.
- Yaegi-safe: no map-holding types in interfaces; `atomic.Value` only `*RangeMembership` and `string`.

**Non-Goals:**

- Reintroducing `pkg/cache`, stream lease, leftover `\x1f`, a `liveStore` type, a named-returns checker, or splitting `lapi` into `lapitransport`/`lapimetrics`/`lapisource`.
- Patricia merge. Changing GitHub `origin/HEAD`.

## Decisions

1. **One Store, two engines.** Dispatch is funcs bound at construct. Rejected: backend interface (Yaegi panics on map-holding types in interfaces); per-method `if mem`/`if red`.
2. **No liveStore.** Live/none memo uses the same `Put`/`Lookup` as stream/alone (memory writes published maps when not ticking).
3. **No leftover path.** Overflow is Warn + origin id 0 on both engines. Redis stores `KindOriginString`, never U+001F leftover.
4. **No stream lease.** Pollers on one Client do not overlap (single-flight). Distinct processes are distinct CrowdSec rows (LAPI+IP). Redis replicas hydrate Range from `range-index`.
5. **Range membership on Store.** `atomic.Value` holds `*RangeMembership`. Hydrate from the blob; skip rebuild when the blob string is unchanged.

## Risks / Trade-offs

- **[Risk] Catalog still names `pkg/cache` until archive Sync** → Mitigation: change deltas are source of truth; archive folds/removes catalog leaves.
- **[Risk] Redis replica lag vs memory publish** → Mitigation: request lookup never retries writer; miss is miss. Same as previous `nextReader` rule.

## Migration Plan

- No Redis key migration for the lease (`updated` is gone). Range blob spelling changes to `cidr=kind` plus optional origin line; cold stream rebuilds from LAPI. Operators: deploy replaces in-process implementation.

## Open Questions

None — explore and implement locked the Store surface.
