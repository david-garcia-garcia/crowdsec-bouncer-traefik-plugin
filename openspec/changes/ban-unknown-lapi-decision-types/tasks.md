## 1. Ingest fail-closed

- [ ] 1.1 In `handleStreamCache`, set `value = cache.BannedValue` in the unknown-type `default` after the existing log.
- [ ] 1.2 In `handleNoStreamCache`, set `value = cache.BannedValue` in the unknown-type `default` after the existing log.

## 2. Tests

- [ ] 2.1 Add a stream test that a `challenge` New decision is cached as `cache.BannedValue` (fails on dest today).
- [ ] 2.2 Add a live test that a `challenge` decision returns `cache.BannedValue` and is cached as that (fails on dest today).
- [ ] 2.3 Cover another unknown type (`allow`) on stream or live, and an empty decision list still `cache.NoBannedValue`.
- [ ] 2.4 Run `go test -count=1 .` on this machine and report pass/fail.
