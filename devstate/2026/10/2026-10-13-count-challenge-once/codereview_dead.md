# Dead

1. [judgement] Dead branch or constant — `pkg/bouncer/bouncer.go:311` — `!match.SkipAppsec` in the challenge-prefix 404 guard is always true on that prefix, because `foldActionRules` clears `SkipAppsec` there and `ServeHTTP` is the only production caller of `serveAppSec`
   Fix: Drop `!match.SkipAppsec` from the guard (the invariant is already documented in core_plugin_appsec.md), or keep it and say it is defense in depth
   Status: skipped
   Argument: Judgement, kept as defence in depth: the guard states its own precondition, so the 404 stays correct if a future caller of `serveAppSec` passes a match that did not go through `foldActionRules`.
