# Explore
IssueKey: 2026-09-19-optcow-stream-lookup

## Concepts

Stream/alone in-memory request lookup today: `ServeHTTP` → `LookupCachedRemediation` → per-key `cache.Client.GetInt`, leftover keys batched through `GetMany`, then `RangeMembership.Remediation` → `iplookup.Helper.Contains` under an **exclusive** mutex (`vendor/.../iplookup/helper.go:72-73`). Stream ticks call `storeStreamDecision` → `cache.Client.Set` into the same `ttl_map.Heap` the request path reads (`pkg/lapi/client_decisions.go`, `pkg/cache/cache.go`). Range membership is already a separate `atomic.Value` on `lapi.Client`, rebuilt when `range-index` changes (`pkg/lapi/client.go`).

Target shape (human lock-in this session):

```
  stream tick (same cadence as hydrateRangeMembership)
       │
       ├─ Load prior map[string]liveSlot (or empty)
       ├─ clone map; apply stream New/Deleted; drop expiresAt <= now
       ├─ Store clone in atomic.Value  (DecisionStore or Client — see OQ)
       └─ hydrateRangeMembership (unchanged blob → RangeMembership snapshot)

  ServeHTTP (stream/alone, memory only)
       │
       ├─ snap := Load() map[string]liveSlot
       ├─ one map probe per Ip + present header keys (same strings as today)
       ├─ skip Range when Ip word is already ban
       └─ else RangeMembership.Remediation(ipAddr) without exclusive-lock on immutable trees
```

`liveSlot { word uint32; expiresAt int64 }` — `word` is packed kind + intern id (`decisionscope.Pack`); `expiresAt` is CrowdSec duration deadline (replaces ttl_map `Data.Timestamp` for Ip/header slots). **One** copy-on-write map only; do **not** keep a writer-only map plus a parallel `uint32` snapshot of the same IPs.

Out of scope unchanged: range-index blob, stream lease key, `intern.Table`, live/none TTL map, Redis, Patricia IP+range merge, stuffing /32s into Helper.

## Decisions

- **Single live map (session correction):** `map[string]liveSlot` published via `atomic.Value`; ticker is the sole writer (clone → apply stream delta → expiry sweep → `Store`). Between ticks readers see one map; during publish two copies until GC. Reject ticket wording that implied `map[string]uint32` plus Range only, and reject dual writer map + uint32 snapshot.
- **Redis / live / none:** keep existing TTL map behavior and `LookupCachedRemediation` cache-client path for those modes.
- **Reclaim / lifetime:** consume `knowledge/devdocs/std_go_reclaim.md` and `core_plugin_lapi_reclaim-key.md`; do not use `sync.Once` or package globals for the snapshot holder — bind to reclaimed `DecisionStore` or `lapi.Client` on Traefik `New` ctx.
- **Metrics / origin:** packed `word` + `DecisionStore.OriginName` on drop unchanged; `intern.Table` stays on DecisionStore.

## Reproduce

**reproduced** on `master` worktree (`go1.x`, windows/amd64), ephemeral probes (not committed):

| Claim | Result |
| --- | --- |
| `LookupCachedRemediation` miss (1 Ip + 1 header scope, Range index present) | ~341 ns/op, **10 allocs/op**, 232 B/op — `GetInt` loop + `GetMany` leftovers + Range path |
| Same with Ip slot packed ban hit | ~351 ns/op, **10 allocs/op** — still merges Range (skip-Range not implemented) |
| `RangeMembership.Remediation` miss | ~50 ns/op, **2 allocs/op** — Helper exclusive lock on read |
| Heap 100k IPv4 packed words: ttl_map `Data` vs `map[string]liveSlot` | **9.55 MiB (~100 B/IP)** vs **6.53 MiB (~68 B/IP)** — matches human/session numbers |

Delivery card must still include sequential + parallel miss benchmarks vs `origin/main` after implement (fixture size TBD below).

## Open questions

- Q: Who owns the client address string used as the Ip cache key?
  Decision: resolved — `pkg/ip.GetRemoteIP` → canonical `req.remoteIP = req.ipAddr.String()` in `pkg/bouncer/bouncer.go` before lookup; reuse that string for snapshot keys, do not re-parse or re-key.
  By: explore

- Q: Where does the live snapshot `atomic.Value` live under reclaim?
  Decision: resolved — **DecisionStore** (shared reclaim value keyed `decisionstore:` + SessionHex + Redis params). Stream ticks on any Client that shares the store publish through the store; not `sync.Once`, not a package global.
  By: explore

- Q: What cache keys stay on the TTL map after Ip/header words move to the live map?
  Decision: assumed — **only non-request-path keys:** stream lease (`updated`), `range-index` blob, and any live/none paths unchanged. Stream/alone Ip and header-scope keys stop `Set`/`GetInt` on the heap for request lookup; no duplicate Ip copies in both stores.
  By: explore

- Q: How do intern-overflow leftover strings (Pack returns `RemediationWithOrigin`) live in `map[string]liveSlot` with only `word` + `expiresAt`?
  Decision: assumed — overflow stays **rare**; slot stores kind-only in `word` (origin id 0) matching today’s overflow metrics behavior, **or** a single optional string side field on `liveSlot` only when `Intern` fails — propose picks one struct; do not add a second parallel Ip map.
  By: explore

- Q: How does Range `Contains` avoid exclusive mutex on immutable snapshot data?
  Decision: assumed — each hydrate builds **new** `iplookup.Helper` trees and publishes via existing `rangeMembership` atomic.Value; request path uses a **read-only** Contains (RLock or forked lock-free read on frozen trees). May need utilities bump or a thin wrapper; do not stuff /32s into Helper.
  By: explore

- Q: How does `LookupCachedRemediation` split stream/alone memory vs live/none without duplicating merge semantics?
  Decision: assumed — add a stream/alone memory entry (or caller flag) that `Load()`s the live map and probes per key; live/none keep `cache.Client` GetInt/GetMany path. Ban-wins merge across Ip, Range, headers unchanged.
  By: explore

- Q: When does the tick publish relative to incremental stream apply?
  Decision: resolved — **once per successful tick** after `fetchAndApplyStreamDecisions` logic is applied into the **clone** of the prior live map (not per-`storeStreamDecision` Set). During the tick, build from Load(previous) + deleted/new + expiry; then single `Store`. `hydrateRangeMembership` stays same cadence (end of tick / lease skip path).
  By: explore

- Q: Where do benchmark numbers for the delivery card live (100k vs 400k, sequential vs parallel)?
  Decision: assumed — new benchmarks beside `pkg/decisionscope` lookup tests and/or `pkg/lapi` stream tests; compare `origin/main` vs branch with `-benchmem`, report heap retained, allocs/op, ns/op miss path; document fixture size in card.
  By: explore

- Q: Does this work reconstruct client address / Host / trust hop?
  Decision: resolved — none; reuse GetRemoteIP output only.
  By: explore
