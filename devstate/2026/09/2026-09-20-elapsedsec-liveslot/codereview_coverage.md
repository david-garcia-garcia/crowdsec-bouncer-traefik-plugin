# Test coverage

1. [hard] Edge case untested — `pkg/decisionstore/liveslot.go:30-40` — `elapsedNow` clamps wall clock step-back via `lastElapsed`; requirement and spec name monotonic elapsed after NTP adjust; no test fails if the clamp loop is removed
   → Assert `elapsedNow()` does not decrease when wall Unix steps backward (inject or stub wall time)
   Status: done
   Argument: TestElapsedNowIgnoresWallStepBack bumps originUnix forward and asserts elapsedNow does not decrease.

2. [hard] Edge case untested — `pkg/decisionstore/liveslot.go:47-55`, `pkg/decisionstore/memory.go:44-64` — memory `durationSec` `0` must not linger after non-zero `PublishTick` (spec scenario “Duration zero does not linger past publish sweep”); only Redis `TestRealRedisDurationZeroIsNotLasting` covers duration `0`, not memory stream/tick publish
   → Memory test: tick `Put` with `DurationSec: 0`, `PublishTick(ElapsedNow())`, assert lookup miss
   Status: done
   Argument: TestMemoryDurationZeroMissesAfterPublish.
