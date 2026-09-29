# Performance

1. [judgement] Hot-path full scan or compile — `pkg/bouncer/bouncer.go:343` — `foldActionRules` walks every compiled row and is recomputed in ServeHTTP helpers
   Fix: Pass the ServeHTTP fold into helpers when a later change needs one walk
   Status: skipped
   Argument: judgement; usage recomputes fold; rule list is config-sized; not applied unattended.
   Quote:
      ```
      func (b *Bouncer) foldActionRules(httpReq *http.Request) actionMatch {
      	for _, i := range b.actionRules.Matching(httpReq) {
      ```
