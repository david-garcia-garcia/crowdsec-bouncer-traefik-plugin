# Explore

## Concepts

### What each backend does with a non-positive TTL today (MEASURED, not read)

Measured on `fad36a1` with a throwaway probe: the in-memory backend in-process, the Redis backend
against a real `redis:7-alpine` container on `127.0.0.1:6399`. The two backends do not agree, and
only one of them is dangerous.

**In-memory (`leprosus/golang-ttl-map`, `vendor/.../map.go:114-142`)**

| Call | What happens |
|------|--------------|
| `Set(k, v, 0)` on a fresh key | `Heap.Set` early-returns on `ttl == 0`. Nothing stored. `Get` → `cache:miss`. |
| `Set(k, v, 0)` on an existing key | Same early return, so **the previous value and its TTL survive**. `Set("x","t",60)` then `Set("x","f",0)` still reads `"t"`. The write is silently lost. |
| `Set(k, v, -1)` / `Set(k, v, -3600)` | Stores with `Timestamp = -1`, and `Heap.Get` skips the expiry check when `Timestamp == -1`. **The entry never expires.** Measured: `Get` → `"t"`, heap timestamp `-1`. |
| `Acquire(k, v, -1)` | Wins once, then **never lets anyone win again**. A permanent stream lease stops that instance's polling for the life of the process. |
| `Acquire(k, v, 0)` | Never stores, so **every** caller wins. No mutual exclusion at all. |

The negative-TTL row is exactly the outcome the ticket names: a cached ban that outlives the decision
that justified it, with no upper bound.

**Redis (`simpleredis.Set`, `vendor/.../commands.go:44-47`)**

`Set` always sends `SET <key> <val> EX <duration>`; there is no guard upstream. Real Redis rejects a
non-positive `EX`:

```
ERR invalid expire time in 'set' command
```

Nothing is written, and `redisCache.set` logs it at ERROR (`cache:setDecisionRedisCache...`) on every
call. `Acquire` fails the same way inside the Lua body and returns that raw error, which in
`handleStreamCache` counts as a poll failure and can flip `isCrowdsecStreamHealthy` — which applies
`CrowdsecLapiFailureAction` (default **ban**) to cache misses.

So: **memory writes an immortal entry, Redis writes nothing and logs an error per call.** Neither is
a no-op, and the divergence means no caller can reason about a non-positive TTL.

### Enumeration of every cache read path

`cacheInterface` has three read verbs: `get`, `getMany`, `acquire`. Complete list of production call
sites (test-only callers excluded):

| # | Path | Verb | Frequency | Does a stale value change the remediation served? |
|---|------|------|-----------|---------------------------------------------------|
| 1 | `decisionscope.readRangeIndex` → `ApplyRangeBatch` (`range.go:87`) | `Get` | once per stream poll | **Yes, and worse.** This is a read-modify-write of the shared Range blob. A stale read rebuilds the index from an old base and writes that truncated blob back to the writer, dropping Range CIDRs **for every instance** until the next `startup=true` resync. |
| 2 | `lapi.Client.hydrateRangeMembership` (`client.go:287`) | `Get` | once per stream poll, plus once at `startStream` | **Yes.** It loads the in-process Range trees that `RangeMembership()` serves on every request. `fetchAndApplyStreamDecisions` calls it immediately after `ApplyRangeBatch` writes, so it is a literal read-after-write. A stale read is then memoised by `storeRangeMembership` as `lastRangeIndex`, so the wrong trees persist until the blob next changes. |
| 3 | `decisionscope.LookupCachedRemediation` (`lookup.go:76`) | `GetMany` | **every request** | **Yes — this is the ticket's defect.** Stream/alone read a miss as "no decision affecting this IP" (`bouncer.go:202-222`), so a just-banned IP that the replica has not received yet is let through. Live mode is partly self-correcting (a miss re-queries LAPI) but a stale stored `f` still short-circuits to allow at `bouncer.go:212`. |
| 4 | `lapi.handleStreamCache` → `Cache().Acquire` (`client_stream.go:80`) | `acquire` | once per stream poll | No. Already writer-only (`rc.writer.Eval`). Correct as the ticket says; untouched. |

## Decisions

### Deliverable 1 — guard placement

The guard goes in `pkg/cache`, not upstream. `simpleredis.Set` is a thin RESP encoder whose contract
is "write for this many seconds"; a non-positive duration is caller error, and Redis rejecting it
loudly is the right behaviour for a transport. There is no defect inside `simpleredis`, so the
stop-and-report fence does not fire.

`delete` takes no duration — there is nothing to guard on that verb. `Client.Delete` keeps its
signature. `Set` and `Acquire` are the two verbs that carry a duration.

`Acquire` is guarded too, and returns `(false, error)` rather than silently succeeding: "no-op" for
an acquire means *you did not win*, and the measured memory behaviour (a lease that never expires,
killing that instance's polling forever) is the same immortal-entry danger the ticket names. It is
unreachable today because `handleStreamCache` clamps `leaseDuration` to at least 1, so this is a
closed hole rather than a behaviour change.

### Deliverable 2 — mechanism

Two different problems hide behind "read your own writes", and they want different answers.

**Paths 1 and 2 (the shared Range index): read the authoritative copy, always.**

A read-modify-write must read the primary; that is not a timing question, it is a correctness
invariant. Reading a replica here can *destroy* data for the whole deployment, which is a strictly
worse failure than serving one stale request. These reads happen once per `updateIntervalSeconds`
(default 60) per instance, so pinning them to the writer costs two round trips a minute and zero
per-request work. Implemented as an explicit `Client.GetConsistent`, not as an implicit rule that
`Get` goes to the writer, so the next author reading the call site can see the intent.

**Path 3 (the per-request lookup): pin a key to the writer for a bounded window after writing it.**

`set` and `delete` record the key with a deadline; `get` / `getMany` use the writer when any
requested key is still inside its window, and otherwise keep the existing round-robin over the read
hosts. The window is a constant in `pkg/cache` (`writerPinWindow`), **not** a configuration knob.

Why this and not the alternatives:

- **Writer-only reads everywhere.** Correct, and explicitly forbidden by the ticket for a good
  reason: `RedisCacheReadHosts` exists to carry per-request lookup load, and taking it away is a
  regression paid by every request in every deployment to close a window that only lagging-replica
  deployments have.
- **One global "recently wrote" deadline** (any write sends all reads to the writer for W). One
  int64, no map, no sweep — very tempting. It degenerates in **live** mode, where the cache is a
  per-request memo and writes never stop, so the window never lapses and every read lands on the
  writer. That is the forbidden outcome reached by accident. Rejected.
- **A local write-through memo in front of Redis.** Gives exact read-your-writes with no round trip
  and no window constant, but introduces a second coherence problem: another instance's `Delete`
  cannot invalidate our memo, so we would serve a ban we were told to drop. Trading a bounded stale
  window for an unbounded one. Rejected.
- **Verify-on-replica** (read the replica, re-read the writer when the value differs from what we
  wrote). Needs the written value kept anyway, and adds a second round trip to the hot path.
  Rejected.
- **Redis `WAIT numreplicas timeout` after each write.** Not on the `simpleredis` surface, and
  adding it is an upstream change the fence forbids. It also moves the cost onto the write path,
  where the stream poller would block on replication. Rejected.

Honest statement of the guarantee: this bounds the stale window to `writerPinWindow`, it does not
abolish staleness. A replica lagging by more than that is a broken deployment and no read routing
inside the plugin can hide it.

Memory is bounded on purpose. The pinned-key map is capped (`writerPinMaxKeys`); a burst larger than
the cap — a `startup=true` stream pull is exactly that — falls back to pinning **all** reads for the
window instead of silently dropping keys and serving stale. Overflow fails safe, toward the writer.

## Open questions

- Q: What is the right value for `writerPinWindow`, given no configuration knob is allowed?
  Decision: assumed — 5s. It is an order of magnitude above healthy Redis replication lag
  (sub-millisecond on a LAN, single-digit milliseconds across an AZ) so it covers realistic lag, and
  it is short against the default `updateIntervalSeconds` of 60, so in stream mode at most ~8% of the
  interval has request reads on the writer. If an operator ever reports a replica lagging longer, the
  answer is to fix the replica, not to widen this constant into a knob.
  By: explore

- Q: Does `Client.GetConsistent` count as new public surface under the fourth gate (permanent cost
  versus benefit)?
  Decision: assumed — no. The gate is about operator-visible surface: config fields, headers, key
  shapes, providers. This is an internal Go method on a plugin-private package, with two call sites,
  and it replaces an implicit rule that would otherwise have to live in a comment.
  By: explore

- Q: Will the two call-site swaps (`range.go`, `client.go`) collide with PR #77
  (`2026-09-18-ip-cache-key-canonicalization`), which is editing `pkg/lapi` and the decision-scope
  paths?
  Decision: resolved — #77 landed as squash `2fedec6`. Merge conflicted only `readRangeIndex`.
  Kept both: `GetConsistent` (this ticket) and miss-vs-error `(string, error)` (#77). A dead replica
  is no longer the unread-index fixture; #77's tests now refuse GET on the writer after seed.
  By: implement

- Q: Is the swallowed cache error at any call site changing behaviour, which would be the one piece
  of evidence that could reopen the out-of-scope third deliverable?
  Decision: resolved — one found, `redisCache.set` dropping a write after logging, and it is
  recorded as a debt note rather than widening this PR, exactly as the ticket directs.
  By: explore
