# Standards

1. [judgement] Leave a trail — `pkg/bouncer/origin_based_decision_remap.go:117` — `appliedLAPIRemediation` keeps a ban the remap would soften, and no log line says the remap was not applied
   Fix: Log TRACE with the rule name when the softened ban is kept
   Status: skipped
   Argument: judgement; the response already carries `ban:lapi:<origin>` and the function has no request to log, so the trace would need another parameter for one line.
