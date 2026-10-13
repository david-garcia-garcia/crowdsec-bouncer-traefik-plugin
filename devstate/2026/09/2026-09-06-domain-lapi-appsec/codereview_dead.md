# Dead

1. [hard] Leftover production path — `pkg/lapi/client.go:350` — `(*Client).Mode` has no callers after bouncer moved mode reads to its own `crowdsecMode` field (`b.crowdsecMode` in `pkg/bouncer/bouncer.go`); grep `.Mode()` across `*.go` excluding `*_test.go` returns zero hits (on `origin/master`, `pkg/bouncer/bouncer.go` had three production calls)
   → Delete `Mode`; bouncer and lapi internals already read `crowdsecMode` directly
   Status: done
   Argument: Deleted (*lapi.Client).Mode; bouncer already reads crowdsecMode.
