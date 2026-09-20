## Why

Memory `LiveSlot` values are 16 bytes on current Go map layouts because `ExpiresAt` is int64 wall Unix beside a uint32 word. Large published maps and BeginTick clones multiply that overhead. Elapsed int32 expiry on a process-local clock shrinks slots to eight bytes while keeping the same expiry predicate, but only if every sweep and `PublishTick` caller uses that clock—not wall Unix.

## What Changes

- Change memory `LiveSlot.ExpiresAt` to int32 elapsed seconds since a package-load `time.Time` (`time.Since` plus bias 2); keep `0` as the PublishTick skip-sweep sentinel.
- Add unexported elapsed clock helpers in `pkg/decisionstore` (no `pkg/elapsedsec`).
- Change `Store.PublishTick` and engine callbacks from `int64` to `int32`; stream apply and tests pass elapsed `now`.
- Align memory lookup, live PutMany COW sweep, and `LiveSlotFromPack` with the elapsed clock; saturate expiry into `[1, MaxInt32]`.
- Update benches that used far-future Unix literals to use `math.MaxInt32` (or equivalent) for `ExpiresAt`.
- Leave Redis PublishTick a no-op and Redis EX TTL as wall duration seconds.

## Capabilities

### New Capabilities

(none)

### Modified Capabilities

- `core_plugin_decisionstore_store`: memory LiveSlot expiry encoding, elapsed clock, and `PublishTick(now int32)` semantics for memory backends.

## Impact

- `pkg/decisionstore` (`liveslot.go`, `memory.go`, `store.go`, tests/benches)
- `pkg/lapi/client_stream.go` (PublishTick argument)
- OpenSpec fold into `core_plugin_decisionstore_store`; devdocs impact deferred to devdocsimpact phase.
