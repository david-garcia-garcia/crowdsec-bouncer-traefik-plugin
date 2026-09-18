## 1. Comments

- [x] 1.1 One-liner on `nextReader`: empty readers → writer; otherwise replica only
- [x] 1.2 One-liner on `get`: miss or replica error is not retried on the writer
- [x] 1.3 One-liner on `set`: Redis error is logged; Set is void
- [x] 1.4 One-liner at stream `int64(duration.Seconds())`: sub-second becomes `0`; no clamp

## 2. Verify

- [x] 2.1 `go test ./pkg/cache/ ./pkg/lapi/ -count=1` stays green
- [x] 2.2 No Redis/memory signature or runtime change; no new test that asserts replica-lag, void Set, EX `0`, or stream `Seconds()` as new policy
- [x] 2.3 README `RedisCacheReadHosts` and cache usage packets stay unchanged
