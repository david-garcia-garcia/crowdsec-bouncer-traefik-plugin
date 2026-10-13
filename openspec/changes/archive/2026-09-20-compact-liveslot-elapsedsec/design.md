## Context

See `proposal.md` — Why. On `master`, memory slots store wall Unix in int64 `ExpiresAt` and callers pass `time.Now().Unix()` into `PublishTick`, lookup, and live COW sweeps. Explore locked int32 elapsed encoding with origin at package `init` in `pkg/decisionstore` only.

## Goals / Non-Goals

**Goals:**

- Eight-byte `LiveSlot` `{uint32, int32}` with unchanged miss predicate shape: expired iff `ExpiresAt > 0 && ExpiresAt <= now`.
- Single clock owner inside `pkg/decisionstore`; exported `Store.PublishTick(now int32)`.
- `PublishTick(0)` continues to skip expiry sweep; duration `0` / `-1` still expire under elapsed encoding.
- Stream apply passes elapsed `now` once per payload.

**Non-Goals:**

- Redis slot encoding, EXAT, captcha cookies, metrics timestamps.
- Packing expiry into `Word` bits or int16 fields.
- New `pkg/elapsedsec` or per-router origin seeds.

## Decisions

1. **Origin at package load** — `elapsedStart = time.Now()` once (monotonic reading kept). `elapsedNow` is `time.Since(elapsedStart)/time.Second + 2`. Bias keeps `0` free for PublishTick sentinel. Alternative (Unix subtract + CAS) rejected: `.Unix()` is wall time; `Since` is the stdlib monotonic clock. Alternative (Store `New`) rejected: would differ per router instance without benefit.

2. **int32 `PublishTick(now)`** — Store and engine use `int32` so wall Unix cannot compile into memory sweep without conversion. Redis engine keeps no-op and ignores the argument. Alternative: named `Elapsed` type — deferred unless implement still mixes clocks.

3. **Expiry saturation** — `LiveSlotFromPack` sets `ExpiresAt` via `now() + durationSec`, clamped to `[1, MaxInt32]` (`1` is already expired); immediate durations miss lookup on the next elapsed `now`. Alternative: store wall Unix in int32 — rejected (Y2038 and wastes the size win).

## Risks / Trade-offs

- **[Risk] Caller passes wall Unix after signature change** → Mitigation: int32 API + update stream apply and tests in same change; spec requires elapsed `now`.
- **[Risk] int32 horizon ~68 years from origin** → Mitigation: acceptable for process lifetime; saturate at MaxInt32.
- **[Trade-off] In-memory slots not portable across process restart** → Already true for memory store; Redis unchanged.

## Migration Plan

Single deploy: no Redis key migration. Memory maps rebuild from stream on restart as today. No config flag.

## Open Questions

None — explore resolved `pkg/elapsedsec` and origin ownership.
