# Code review
Pin: origin/master...HEAD excluding `devstate/` and `.cursor/`

## Standards
1. [hard] Name for the scope — `pkg/simpleredis/simpleredis.go:203` — `do` is a vague verb; callers must read the body to learn it is a deadline + write + read round-trip
   → Rename to the job, e.g. `roundTrip`
2. [hard] Name for the scope — `pkg/simpleredis/simpleredis.go:210` — `clean` hides “the RESP reply was fully parsed”
   → Name the result `parsed` or `reusable`
3. [hard] Leave a trail — `pkg/simpleredis/simpleredis.go:41` — `pooledConn` and unexported methods lack job comments; `Init` omits do-not-copy
   → Add job comments; rewrite `Init`/`SimpleRedis` comments
4. [hard] Leave a trail — `pkg/cache/cache.go:116` — writer/readers became pointers with no comment that `Init` installs a pool mutex that must not be copied
   → One-line comment at the allocation
5. [hard] Leave a trail — `pkg/simpleredis/simpleredis_test.go:13` — `fakeRedis` helpers have no job comments
   → Add comments
6. [hard] Leave a trail — `tests/e2e/mock/mocklapi/main.go:93` — `readRedisCommand` has two parse modes with no block intros
   → Comment RESP vs inline paths

## Spec
none

## Security
none

## Performance
none

## Applied
- Standards 4: comment on `pkg/cache/cache.go` pointer hold after Init
- Standards 6: RESP vs inline block comments in `readRedisCommand`

## Recorded and skipped
- Standards 1, 2, 3, 5: copied `pkg/simpleredis` is pinned to simpleredis@f8801cc (PR #8). Renaming `do`/`clean` or restyling that tree would diverge from the pin. golangci excludes `pkg/simpleredis/`.

Standards: 6 findings, worst: Name for the scope at `pkg/simpleredis/simpleredis.go:203` (skipped — pinned copy)
Spec: 0 findings, worst: none
Security: 0 findings, worst: none
Performance: 0 findings, worst: none
