# Test coverage

1. [judgement] Happy path only — `pkg/bouncer/bouncer.go:187` — Redis fail-closed was retargeted onto `Bouncer.redisUnreachableBlock`; no ServeHTTP test hits `CacheUnreachable`
   → Assert unreachable + `redisUnreachableBlock` true bans and false passes, or skip: DestBranch also lacked a request-path fixture
   Status: skipped
   Argument: judgement; DestBranch also lacked a ServeHTTP Redis-unreachable fixture.
