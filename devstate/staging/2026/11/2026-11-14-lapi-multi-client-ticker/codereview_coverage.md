# Test coverage

1. [judgement] Assertion does not prove the job — `pkg/lapi/client.go:335` — `fire` runs `work()` and only then `Reset(interval)` (fixed delay, no overlapping `work()` from one timer, the shape the spec SHALLs); no test fails if the timer re-armed before `work()` or ran fixed-rate, because `Test_pollTimer_stopDuringWorkDoesNotRearm` calls `stop` microseconds after the first `work()` enters, well inside the 1 ms interval
   Quote:
   ```
   client.go:335-344  if p.isStopped() { return }; work(); p.mu.Lock(); if !p.stopped { p.timer.Reset(interval) }
   zzz_poll_timer_test.go:92  <-entered; poll.stop(); close(release)
   ```
   Fix: Block the first `work()` for several intervals before stopping and assert no second `work()` started while it ran
   Status: done
   Argument: Added `Test_pollTimer_workRunsBeforeRearm`: 1 ms interval, 10 ms work, fails if one timer runs two `work()` calls at once.
