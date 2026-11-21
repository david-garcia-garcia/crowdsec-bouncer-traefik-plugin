# tokenbucket Allow at utilities v1.0.7

What the published `tokenbucket` package does at the tag this plugin pins (`v1.0.7` = `42e6a1a967155318023c4defe491d1d423e165b6`), and the fail-open defect still in it. Measured 2026-11-20 from a `git archive v1.0.7` copy.

## Surface

- `NewMemory(rate float64, burst int64, maxDelay, ttl time.Duration)` and `NewRedis(redis, rate, burst, maxDelay, ttl)`. Rate, burst, maxDelay, and ttl are fixed per limiter, so one limiter per bucket. `Allow(ctx, key) (allowed bool, wait time.Duration, err error)`. Owner: `memory.go`, `redis.go`, `clock.go`. Extract: `.sources/clock-memory-redis-go.md`.
- Validation at New: rate finite and > 0; burst ≥ 1; maxDelay ≥ 0; ttl a whole number of seconds ≥ 1s. Owner: `clock.go` `validateClock`.
- The Memory store caps at 65536 keys and evicts an arbitrary live key at the cap (that key gets a fresh burst). Owner: `memory.go` `maxMemorySources`, `dropOne`.
- The Redis store sends one `EVAL` (Traefik's Lua, seeded to a full bucket) per `Allow`. Owner: `lua.go`, `redis.go`.
- The package comment says Yaegi-safe. Upstream `TestYaegi_AllowBurst` and `TestYaegi_AllowRefund` (yaegi v0.16.1) pass at v1.0.7. Live variants skip without a server (test run).

## Fail-open at v1.0.7 (upstream PR #54 open)

Refund and admit use different units. `consumeOne` refunds when `waitMicro > maxDelay.Microseconds()`; `Allow` admits when `waitDuration(waitMicro) <= maxDelay`, and `waitDuration` truncates to whole nanoseconds. A refunded consume can still be admitted. Owner: `clock.go` `consumeOne`, `waitDuration`, `allowedFromWait`; `memory.go` / `redis.go` `Allow`.

- Branch tests from PR #54 (`TestAllow_MaxDelayZeroWaitDurationTruncFailOpen`, `TestAllow_MaxDelayTruncationFailOpen`, `TestRedis_MaxDelayTruncationFailOpen`, `TestAllow_WaitDurationOverflowFailOpen`) all **fail** on v1.0.7 code (test run).
- Rate-limiter shape (maxDelay = 0, deny instead of delay), Memory store, 1,000,000 hits 0–2µs apart (a hot key under flood), compared with the same `consumeOne` whose admit is decided in microseconds: rate 50/s burst 100 → 188 admitted vs 149; rate 1000/s burst 1000 → 3029 vs 1999. With hits ≥ 1ms apart the two agree. authority: source (throwaway probe test on the v1.0.7 copy; not committed anywhere).
- The returned `wait` is the truncated Duration, so a caller cannot tell a refunded admit from a real one. No workaround exists on the published surface. authority: inference from the signatures above.

Other reproduced defects (non-finite rate, non-finite Eval wait, ttl seconds, new-key fill, `last` rewind) are fixed at v1.0.7: their `TestRepro_*` pass.

## Upstream fix status

PR #54 is open, unmerged, and in no tag. No commit touches `tokenbucket/` between `v1.0.7` and `v1.0.8` / `origin/master`. Extract: `../ext_traefik-middleware-utilities_windowcounter/.sources/upstream-prs.md`.
