# Deviations

- [x] taken  `appsec.Client.Query` also receives the per-request read-deadline control
  Asked: a total read deadline on bodies of unknown length that blocks independently of `bouncerAppsecFailureAction` (decisions 1 and 2); no criterion names a `Query` signature change.
  Instead: `Query` gains a parameter carrying the `http.ResponseController` the bouncer builds from its `rw`, so the deadline timer can cut an HTTP/1.1 read (`Body.Close` cannot, measured). 1 production call site (`pkg/bouncer/bouncer.go:458`) and 43 test call sites in `pkg/appsec` migrate in this change.
  Owner: `pkg/appsec/query.go` (`Client.Query`); `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`, sole owner of `rw`)
  Why: the response writer is the only handle that sets a read deadline on HTTP/1.1 and HTTP/2; the bouncer owns it, the AppSec client owns the read. Rank `bounded incidental` (explore.md, open question on distinguishing the deadline from a client disconnect).
  By: explore
  Requester: not asked
