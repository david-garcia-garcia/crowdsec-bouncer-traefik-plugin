## 1. Immutable Box publish

- [x] 1.1 In `pkg/bouncer/bouncer.go` `storeBinding`, always `dest.Store(&reclaim.Box{Value: value})`. Remove the in-place `boxed.Value = value` branch when `dest.Load()` already holds `*reclaim.Box`.
- [x] 1.2 Leave `ReceiveLAPI` / `ReceiveAppSec` / `ReceiveCaptcha`, `Unbox`, and `Watch` unchanged. Do not take Findings 2 or 3. Do not refactor unrelated bouncer policy.

## 2. Test helper companion

- [ ] 2.1 In `pkg/reclaim/zzz_alias_test.go` `watchInto`, Store a new `*reclaim.Box` on every update (same publish shape as `storeBinding`). Do not assign `boxed.Value` in place. — human override: leave unbuilt; deviations.md stays `[ ] proposed`.
- [x] 2.2 Leave `zzz_bind_test.go` helpers that Store a bare `*Client` alone this change.

## 3. Proof

- [x] 3.1 Add a focused concurrent Unbox-vs-Store test for the publish shape (bouncer binding and/or reclaim helper).
- [x] 3.2 Run `go test ./pkg/bouncer/ ./pkg/reclaim/ -count=1`. Where cgo/`gcc` exists, also run with `-race`. If the race detector is unavailable, note that on the implement card and still land the Store fix.

## 4. Leave neighbors

- [x] 4.1 Do not change reclaim Watch/Unbox/Published API. Do not invent a new catalog leaf. Usage Gotchas already on `knowledge/devdocs/core_plugin_middleware_instance-slots.md` and `std_go_reclaim.md` — verify at devdocsimpact, do not rewrite unless they drift.
