# Deviations

- [x] taken  `appsec.Client.Query` also receives the per-request read-deadline control
  Asked: a total read deadline on bodies of unknown length that blocks independently of `bouncerAppsecFailureAction` (decisions 1 and 2); no criterion names a `Query` signature change.
  Instead: `Query` gains a parameter carrying the `http.ResponseController` the bouncer builds from its `rw`, so the deadline timer can cut an HTTP/1.1 read (`Body.Close` cannot, measured). 1 production call site (`pkg/bouncer/bouncer.go:458`) and 43 test call sites in `pkg/appsec` migrate in this change.
  Owner: `pkg/appsec/query.go` (`Client.Query`); `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`, sole owner of `rw`)
  Why: the response writer is the only handle that sets a read deadline on HTTP/1.1 and HTTP/2; the bouncer owns it, the AppSec client owns the read. Rank `bounded incidental` (explore.md, open question on distinguishing the deadline from a client disconnect).
  By: explore
  Requester: not asked
- [x] taken  HTTP/1.1 stall behind Traefik is blocked when the body ends, not at the deadline
  Asked: a total read deadline that blocks a body of unknown length (decisions 1 and 2); spec scenario "Stalled HTTP/1.1 chunked body is blocked" said the ban arrives without waiting for the client to end its body.
  Instead: measured on Traefik v3.7.11 (mock e2e): `http.ResponseController` does not reach the HTTP/1.1 connection through Traefik's writer, so the read is not cut; the fired timer still blocks the request once the client ends or abandons its body, or at Traefik's `readTimeout`. Spec scenario, README, and e2e assert that measured behaviour; HTTP/2 is cut at the deadline.
  Owner: `pkg/appsec/query.go` (`readClientBodyForAppsec`); Traefik's `ResponseWriter` chain (outside this repo)
  Why: design Risks and tasks 6.3 named this outcome ("adjust the assertion to the measured behaviour … keep the request blocked"). Follow-up: `knowledge/debt/2026-11-14-appsec-body-timeout-http1-cut-behind-traefik.md`.
  By: implement
  Requester: not asked
