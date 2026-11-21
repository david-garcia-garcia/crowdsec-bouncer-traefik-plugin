# Test coverage

1. [judgement] Edge case untested — `pkg/lapi/client_live.go:75` — `liveDecisionLeft` special-cases a non-positive LAPI duration as zero; no test drives LiveLookup with such a ban, so reverting the branch stays green (the writer's `decisionLeft > 0` gate still hides it at HTTP level)
   Quote:
   ```
   if duration <= 0 {
       return 0
   }
   test: (none) — no LiveLookup test in pkg/lapi or pkg/bouncer uses a 0s or negative ban duration
   ```
   Fix: In `pkg/lapi/zzz_decision_left_test.go`, assert LiveLookup of an active ban with duration `0s` (or negative) returns kind ban, decisionLeft 0, and a memo slot with DecisionEnd 0
   Status: skipped
   Argument: judgement; the branch cannot change the HTTP outcome (the writer gates on `decisionLeft > 0`), and LAPI does not return active decisions with a non-positive duration.
