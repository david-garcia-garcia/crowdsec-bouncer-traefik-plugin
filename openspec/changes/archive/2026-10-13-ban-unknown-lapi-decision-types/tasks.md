## 1. Ingest fail-closed

- [x] 1.1 In `handleStreamCache`, set `value = cache.BannedValue` in the unknown-type `default` after the existing log.
- [x] 1.2 In `handleNoStreamCache`, set `value = cache.BannedValue` in the unknown-type `default` after the existing log.

## 2. Tests

- [x] 2.1 Add a stream test that a `challenge` New decision is cached as `cache.BannedValue` (fails on dest today).
- [x] 2.2 Add a live test that a `challenge` decision returns `cache.BannedValue` and is cached as that (fails on dest today).
- [x] 2.3 Cover another unknown type (`allow`) on stream or live, and an empty decision list still `cache.NoBannedValue`.
- [x] 2.4 Run `go test -count=1 .` on this machine and report pass/fail.
