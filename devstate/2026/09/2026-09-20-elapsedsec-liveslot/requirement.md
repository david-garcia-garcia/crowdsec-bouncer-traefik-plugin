# Requirement
IssueKey: 2026-09-20-elapsedsec-liveslot

## Problem
Memory-backed DecisionStore maps hold one `LiveSlot` per IP or header-scope key. With `ExpiresAt` as int64 Unix seconds the struct is 16 bytes (uint32 + padding + int64), inflating RSS for large published maps and their BeginTick clones (~27 MiB saved at 1M keys per the caller measurement on Go 1.25 swiss maps).

## Current (code)
- `LiveSlot` is `{Word uint32, ExpiresAt int64}`. `pkg/decisionstore/liveslot.go`
- `LiveSlotFromPack` sets `ExpiresAt: time.Now().Unix() + durationSec`. `pkg/decisionstore/liveslot.go`
- Memory `PublishTick(now)` drops tick slots when `ExpiresAt > 0 && ExpiresAt <= now`. `pkg/decisionstore/memory.go`
- Live `PutMany` (not ticking) sweeps published map with `time.Now().Unix()` and the same predicate before COW. `pkg/decisionstore/memory.go`
- `LookupRemediation` compares `ExpiresAt` to `time.Now().Unix()` with the same predicate. `pkg/decisionstore/memory.go`
- `PublishTick(0)` skips expiry sweep (tests rely on this). `pkg/decisionstore/memory.go` `pkg/decisionstore/zzz_memory_test.go`
- `TestMemoryExpiryOnPublish` uses `DurationSec: -1` and `PublishTick(time.Now().Unix())` to assert immediate miss. `pkg/decisionstore/zzz_memory_test.go`
- Stream apply defers `PublishTick(time.Now().Unix())`. `pkg/lapi/client_stream.go`
- Redis `PublishTick` is a no-op; Redis PutMany uses `DurationSec` as EX TTL seconds. `pkg/decisionstore/redis.go`
- Lookup benches seed `ExpiresAt: 9_999_999_999`. `pkg/decisionstore/zzz_lookup_bench_test.go`
- Process-wide `elapsedsec` clock or `pkg/elapsedsec`: not found.
- OpenSpec memory store text describes `expiresAt` on `LiveSlot` without int32 elapsed encoding. `openspec/specs/core_plugin_decisionstore_store/spec.md`

## Desired
- Change `LiveSlot.ExpiresAt` to int32 storing elapsed seconds since a process-wide origin (init-time wall Unix minus bias 2), not wall Unix in the field.
- Provide `elapsedsec` naming: `Now()` = wall Unix − origin; saturate slot expiry into `(1, MaxInt32]` from `durationSec`; clamp `Now()` on clock step-back to bias; keep predicate `ExpiresAt > 0 && ExpiresAt <= now`.
- Keep `PublishTick(0)` as skip-sweep sentinel; duration `0` and `-1` still expire correctly under the new encoding.
- All memory expiry comparisons and `PublishTick` callers pass elapsed `now`, not `time.Now().Unix()` mixed with elapsed slot values (including `pkg/lapi/client_stream.go` and tests).
- Benches using far-future Unix literals use `math.MaxInt32` (or equivalent) for `ExpiresAt`.
- Keep Redis PublishTick no-op and Redis TTL as wall duration seconds; captcha cookies, metrics, Redis EXAT stay wall Unix.
- Place origin unexported beside LiveSlot in `pkg/decisionstore` unless explore finds a second Unix-shaped consumer warranting `pkg/elapsedsec`.

## Affected
- `pkg/decisionstore/liveslot.go`, `memory.go`, tests and benches under `pkg/decisionstore/`
- `pkg/lapi/client_stream.go` (PublishTick argument)
- Tests calling `PublishTick(time.Now().Unix())` under `pkg/lapi/`, `pkg/decisionstore/`
- OpenSpec / devdocs for memory slot expiry (propose phase)

## Out of scope
- Redis slot encoding or stream TTL clamp on Redis
- Packing expiry into `Word` leftover bits
- int16 expiry field
- Changing `intern.Table`
- Switching the caller checkout (`2026-09-20-memory-liveslot-map`)

## Unknowns
- Whether a second package needs the same elapsed clock API (explore decides `pkg/elapsedsec` vs unexported origin in decisionstore).
- OpenSpec delta wording for `PublishTick(now)` semantics on the public Store API (elapsed vs Unix documented for callers).

## Tensions
- Ticket requires elapsed `PublishTick` at stream apply; dest passes wall Unix from `time.Now().Unix()`. `pkg/lapi/client_stream.go`
- Ticket requires lookup/sweep to use elapsed clock; dest `LookupRemediation` and live PutMany use wall Unix. `pkg/decisionstore/memory.go`
- Committed spec still describes generic `expiresAt` on LiveSlot without int32 elapsed encoding. `openspec/specs/core_plugin_decisionstore_store/spec.md`
- Caller cites memory savings on a parallel branch (`memory-liveslot-map`); dest `master` still has int64 `ExpiresAt`. `pkg/decisionstore/liveslot.go`
