# Test coverage

1. [judgement] Byte series unasserted — `pkg/bouncer/zzz_bouncer_test.go:315` — the spec says the callback relay MUST NOT increment dropped in unit `byte` as well as `request`, but the test reads only `TestDroppedCount`
   Fix: Also assert `TestDroppedByteCount("appsec", "ipv4")` is 0 on the submit path and above 0 on `/protected`
   Status: done
   Argument: The regression test now reads `TestDroppedByteCount` too: `/protected` has bytes > 0, `/crowdsec-internal/challenge/submit` has 0 (pkg/bouncer/zzz_bouncer_test.go `testChallengeDropped`).
