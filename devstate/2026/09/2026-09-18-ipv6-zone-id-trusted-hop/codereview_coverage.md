# Test coverage

1. [hard] Edge case untested — `pkg/ip/checker.go:88` — IPv4 with `%` stays unparseable (colon guard); no test would fail if that guard were dropped
   → Assert `Contains("192.0.2.1%eth0")` errors and a hop `192.0.2.1%eth0` stays fail-closed
   Status: done
   Argument: Added Contains and hop regressions in d6596a2.
