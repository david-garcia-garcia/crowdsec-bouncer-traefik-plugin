# windowcounter sliding window at utilities v1.0.7

What the published `windowcounter` package does at the tag this plugin pins (`v1.0.7` = `42e6a1a967155318023c4defe491d1d423e165b6`), and which reproduced defects are still in it. Measured 2026-11-20 from a `git archive v1.0.7` copy, not from the untracked `BUGS.md` notes in a local clone.

## Surface

- `New(*simpleredis.SimpleRedis, syncRate time.Duration) (*Limiter, error)`. Nil Redis or negative `syncRate` fails. Positive `syncRate` below 20ms floors to 20ms. `0` is exact mode. Owner: `limiter.go` `New`. Extract: `.sources/limiter-go.md`.
- `(*Limiter).Take(ctx, key, limit int64, window) (allowed bool, estimated float64, err error)`. One Limiter serves any number of keys, limits, and windows; limit and window are per call. `Peek` is the same without the increment. `Sleep` / `Wake` / `Close` are reclaim-shaped lifecycle hooks (flush, then stop / start the AfterFunc flush timer). Owner: `limiter.go`.
- Redis only. No in-memory store exists in the package. Owner: `limiter.go` (no other store type).
- Window must be at least 1s and a whole number of seconds; anything else is an error from `Take`, not from `New`. Owner: `limiter.go` `slidingAt`. A caller that wants a config-time error validates itself.
- Redis keys are `<opaque key>:<window start unix>`. Exact mode: `INCR`, `EXPIRE 2×window` on the first hit, `GET previous`. Buffered mode: GET on first sight, admit from `redisKnown + localDelta`, flush deltas with one `EVAL` per dirty key per tick. Owner: `limiter.go` `takeExact`, `takeBuffered`, `flushPendingLocked`, `redisWindowKey`.
- A hit is counted even when it is denied (increment, then compare). Owner: `limiter.go` `takeExact` / `takeBuffered`.
- Buffered outage: `Take` returns the locally computed `allowed` **and** a non-nil error (retained flush error, or a probe GET after one missed `syncRate`). Owner: `limiter.go` `bufferedOutageErrorLocked`. Open upstream PR #62 would change this to `err=nil` with a per-node cap; it is in no tag.
- The package comment says Yaegi-safe. Upstream `TestYaegi_*` (yaegi v0.16.1) pass at v1.0.7: `TakeUntilDeny`, `PeekThenTake`, `BufferedShareSleepDoesNotHang`, `MethodFlushStopDoesNotHang`. Live Redis variants skip without a server. Owner: `limiter_yaegi_test.go`, `yaegi_flush_stop_test.go` at the tag (test run).

## Defects at v1.0.7

| Defect | State at v1.0.7 | Evidence |
|---|---|---|
| Fractional window accepted | fixed (#58) | `TestRepro_FractionalWindowAccepted` passes |
| Mutex held across Redis GET | fixed (#59) | `TestRepro_BufferedTakeHoldsLockDuringRedisGet` passes |
| Concurrent Sleep/Wake hang | fixed (#61) | `TestRepro_SleepWakeRaceHangs` passes |
| Peek vs Take at exactly `limit` | documented occupancy (#64) | `TestRepro_PeekAllowsWhenNextTakeDenies` passes |
| Buffered previous window never re-read from Redis | **present** (PR #63 open) | branch test `TestRepro_BufferedStalePreviousAtBoundary` fails on v1.0.7: `allowed=true estimated=2; want denied estimated=3` |
| Exact-mode EXPIRE not retried after a failed first EXPIRE | **present** (PR #60 open) | `takeExact` sends `Expire` only when `Incr` returns 1 |
| Buffered outage contract | error + local verdict; PR #62 open would return nil | `bufferedOutageErrorLocked` |

Effect of the two present defects (authority: inference from the code above):

- Stale previous: only with `syncRate > 0` and more than one Limiter sharing Redis (replicas). At a window roll a node that flushed before its peers keeps its own lower previous count, so it can admit up to `(true previous − its previous) × weight` extra hits during the next window. Exact mode is not affected.
- EXPIRE leak: a transient EXPIRE failure leaves that one `<key>:<window start>` without a TTL. The key is never reused (the next window has a new start), so the effect is a leaked Redis key, not a stuck deny.

## Upstream fix status

PRs #60, #62, #63 are open on `david-garcia-garcia/traefik-middleware-utilities` (GitHub search, 2026-11-20). No commit touches `windowcounter/` between `v1.0.7` and `v1.0.8` / `origin/master`. Extract: `.sources/upstream-prs.md`.
