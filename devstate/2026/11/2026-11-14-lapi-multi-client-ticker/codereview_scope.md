# Scope

1. [judgement] Scope vs Requirements — `pkg/lapi/zzz_poll_timer_test.go:159` — Desired (`requirement.md:21`) asks for a yaegi test with several loops of the same kind that fails on master; `TestYaegi_pollTimer_manyLoopsStopIndependently` fails on master only because `StartPollTimerForTest` does not exist there, and its assertions (stopped loops freeze, live loops advance) do not count per-loop ticks, so a select-based loop behind the same export would very likely still pass; the master-failing gate is the native AST guard `Test_lapiHasNoSelectStatement` (`pkg/lapi/zzz_poll_timer_test.go:22`) plus the throwaway reproduction recorded only in `explore.md`
   Fix: Record on the delivery card that the master failure is carried by the AST guard and the explore reproduction (explore decision), or accept the yaegi test as proof of the new loop only
   Status: skipped
   Argument: Explore decision: the master failure is carried by the AST guard (fails on master with 3 `select` statements) and the 200 000-tick yaegi reproduction recorded in explore.md; the yaegi test proves the new loop. The delivery card Implementation states this.
