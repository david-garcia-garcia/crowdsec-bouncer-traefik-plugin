# Explore
IssueKey: 2026-09-19-optcow-stream-lookup

**Verdict:** `in progress` — RETHINK `chat-store-split` addressed in propose (store split OpenSpec); implement must replace bolt-on branch code per regenerated tasks.

## Change intent

Lift stream/alone **Ip and header-scope** put, delete, tick publish, and request lookup off `cache.Client` and off `lapi.Client` scratch state. One **stream store** abstraction with two backends:

- **Redis:** same keys as today via `cache.Client` Set/Delete/Get (no COW map).
- **Memory:** one `atomic.Value` holding `map[string]liveSlot{word uint32, expiresAt int64}`; tick clones, applies stream New/Deleted, sweeps expiry, single `Store`; lookup `Load` + one probe per key, skip Range when Ip is already ban.

`DecisionStore` (reclaim value on Traefik `New` ctx) owns `cache.Client` **and** the stream-store implementation. `lapi.Client` applies stream deltas and serves lookup **only through that store** — no `liveTick`, no `if liveTick != nil`, no `UsesLiveSnapshot` / `LookupLiveSnapshotRemediation` switches in Client or bouncer.

```
  OpenDecisionStore(ctx) ──► DecisionStore (reclaim)
        │
        ├── cache.Client     lease, range-index blob, live/none memo (unchanged this ticket)
        └── streamStore      Put / Delete / BeginTick / PublishTick / LookupRemediation
                 ├── redis  ──► cache Set/Delete/Get path (today’s Redis stream keys)
                 └── memory ──► COW map[string]liveSlot

  fetchAndApplyStreamDecisions
        └── streamStore.BeginTick → apply storeStreamDecision/delete → PublishTick

  ServeHTTP (stream/alone)
        └── lapiClient.LookupStreamRemediation(...)   // single entry; no mode branch in bouncer
```

Replace the current PR implementation (`Client.liveTick`, `publishLiveTick`, bouncer `UsesLiveSnapshot` branch). Do **not** extend that bolt-on.

## Concepts

**Defect (RETHINK):** Branch optimized memory lookup with a third store on `Client` while stream apply still branches `liveTick != nil` vs `cacheClient.Set` (`pkg/lapi/client_decisions.go`). Domain should be: backend chosen once at `OpenDecisionStore` (Redis vs memory), Client always calls the store.

**Memory slot:** Packed remediation in `word`; CrowdSec duration as `expiresAt`. **No** `Leftover` string field on the slot (human lock). Intern table overflow: **Warn**, store kind-only in `word` (origin id 0); **no** GetMany / leftover-string serving on the memory path.

**Range:** Still `Client.rangeMembership` `atomic.Value` + `range-index` on `cache.Client`. Lookup merge unchanged (ban wins). Vendor `iplookup.Helper.Contains` already uses `RLock` on immutable trees published at hydrate time — requirement “not exclusive Lock” is satisfied on current vendor; do not stuff /32s into Helper.

**Out of scope (unchanged):** live/none packing onto memory map; removing Redis/live `GetMany`; Patricia merge; changing `origin/HEAD`.

**Pin:** Compare benchmarks and delivery narrative to **`origin/master`**, not frozen `main`. PR #118 retargeted to `master`.

## Decisions

- **Store split (RETHINK / human):** Stream Ip/header lifecycle lives on a dedicated store with Redis and memory implementations; Redis delegates to `cache.Client`; memory uses the single COW map. `cache.Client` remains utility for lease, range-index, live/none memo.
- **No Client liveTick (human):** Remove `liveTick`, `publishLiveTick`, `UsesLiveSnapshot`, and bouncer lookup branching. Stream apply always mutates the store (memory: in-tick clone owned by store, not Client field).
- **Memory slot shape (human):** `liveSlot{word, expiresAt}` only; drop `LiveSlot.Leftover` and tests that assert overflow strings in slots; overflow → Warn + kind-only word.
- **Reclaim (human + devdocs):** `DecisionStore` stays the reclaim value (`decisionstore:` + SessionHex + Redis params). Stream store state lives on that value, not `sync.Once` or package globals. Traefik constructor `ctx` is the holder (`core_plugin_lapi_reclaim-key.md`).
- **Client IP key (reuse):** `pkg/ip.GetRemoteIP` → `req.remoteIP` in bouncer; same string for map keys — no second IP map or re-parse.
- **Tick cadence:** One publish per successful stream apply tick (after full delta applied to clone), not per `storeStreamDecision`. `hydrateRangeMembership` cadence unchanged.
- **Implement strategy:** Revert/replace bolt-on deltas on this branch; OpenSpec propose artifacts must be regenerated (only `tasks.md` present; no committed `proposal.md`/`design.md` for this change id after RETHINK).

## Reproduce

**reproduced** (windows/amd64, worktree HEAD, 2026-09-19):

| Claim | Result |
| --- | --- |
| Branch bolt-on: `Client.liveTick` + `UsesLiveSnapshot` in bouncer | Present — confirms wrong split to remove |
| `LookupCachedRemediation` miss (100k fixture, branch bench) | ~408 ns/op, **12 allocs/op**, 248 B/op |
| `LookupLiveSnapshotRemediation` miss (same fixture) | ~86 ns/op, **1 alloc/op**, 8 B/op |
| Parallel miss live vs cached | ~6.8 ns vs ~153 ns; 1 vs 12 allocs |
| Heap 100k packed Ips: TTL map vs live map (branch bench) | ~18.4 MiB vs ~8.9 MiB retained per build |
| Range read lock | `iplookup.Helper.Contains` uses `RLock` (vendor) |

Master has no live benchmarks yet; delivery card should add comparable benches on `origin/master` baseline when implement lands.

## Open questions

- Q: What is the stream-store surface — methods on `DecisionStore` vs small interface field `streamStore`?
  Decision: **resolved (propose)** — private `streamStore` interface field on `DecisionStore` in `pkg/lapi`; merge helper in `pkg/decisionscope`; Put/Delete keyed like today; memory BeginTick/PublishTick; Lookup merges Ip, headers, Range with ban-wins rules.
  By: propose

- Q: How does Redis implementation handle tick API?
  Decision: **resolved (propose)** — `BeginTick`/`PublishTick` on the shared interface; Redis implementation no-ops; Put/Delete go straight to `cache.Client`.
  By: propose

- Q: Who calls lookup — bouncer vs Client vs DecisionStore?
  Decision: **resolved (propose)** — `Client.LookupStreamRemediation(remoteIP, ipAddr, scopes)` delegates to DecisionStore stream store + `RangeMembership()`; bouncer always calls it for stream/alone; live/none unchanged.
  By: propose

- Q: Intern overflow without `Leftover` on the slot?
  Decision: **resolved (human)** — Warn on intern overflow; slot stores packed kind with origin id 0; lookup returns kind without origin name (matches today’s overflow metrics posture); no GetMany for overflow on memory path.
  By: explore

- Q: Does Range need a utilities change for lock-free read?
  Decision: **resolved** — immutable snapshot + existing `RLock` on `Contains` is enough; no exclusive lock on request path for published trees.
  By: explore

- Q: Benchmark baseline branch for delivery card?
  Decision: **resolved** — **`origin/master`**, sequential + parallel miss, heap retained; fixture 100k documented on card (400k optional follow-up).
  By: explore

- Q: Persist destBranch `master` vs repo `origin/HEAD` → `main`?
  Decision: **none** — ticket-only on `requirement.md`; no devdocs owner for default branch policy (`Persist: none` on RETHINK row).
  By: explore

## Blocked

None for explore. **Propose** is blocked on naming the store interface and rewriting OpenSpec artifacts; **implement** must not proceed until propose reflects RETHINK (replace bolt-on).
