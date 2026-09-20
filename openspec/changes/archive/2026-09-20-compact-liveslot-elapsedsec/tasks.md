## 1. Elapsed clock and LiveSlot shape



- [x] 1.1 Add package-init origin and unexported elapsed `now()` with step-back clamp in `pkg/decisionstore`

- [x] 1.2 Change `LiveSlot.ExpiresAt` to int32; update `LiveSlotFromPack` saturation into `[1, MaxInt32]`

- [x] 1.3 Change `Store.PublishTick` and memory/redis engine signatures to `int32`



## 2. Memory expiry paths



- [x] 2.1 Update memory `PublishTick`, lookup, and live PutMany COW sweep to use elapsed `now()` and the int32 predicate

- [x] 2.2 Preserve `PublishTick(0)` skip-sweep behavior and duration `0` / `-1` test semantics



## 3. Callers and tests



- [x] 3.1 Pass elapsed `now` from `pkg/lapi/client_stream.go` on stream apply

- [x] 3.2 Update decisionstore and lapi tests that used `time.Now().Unix()` for PublishTick or slot expiry

- [x] 3.3 Update lookup benches to seed `ExpiresAt` with `math.MaxInt32` (or equivalent) instead of far-future Unix literals



## 4. Verification



- [x] 4.1 Run `go test ./pkg/decisionstore/... ./pkg/lapi/...` and confirm memory expiry tests pass

- [x] 4.2 Confirm Redis paths unchanged (PublishTick no-op, EX TTL from duration)

