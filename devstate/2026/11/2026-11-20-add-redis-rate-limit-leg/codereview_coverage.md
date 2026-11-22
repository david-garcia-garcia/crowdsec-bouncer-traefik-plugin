# Test coverage

1. [hard] Assertion does not prove the job — `pkg/bouncer/zzz_servehttp_gaps_test.go:126` — the leg-table refactor moved LAPI's stream-scope WARN into a bind hook that `ReceiveLAPI` wires (`pkg/bouncer/bouncer_leg_lapi.go:21`), but the edited test now calls `traceBinding` and passes `b.warnMissingStreamScopes` itself, so it stays green if `ReceiveLAPI` passes `nil` or another hook; no other test (unit, root, Pester) asserts `crowdsec bouncer stream scopes missing`
   Fix: Drive `b.ReceiveLAPI(reclaim.Published{Value: client})` twice on a route with `lapiLeg.subscribed` and a header scope the client does not poll; assert exactly one WARN naming the scope, and none without header scopes
   Status: done
   Argument: TestReceiveLAPI_* now drive `b.ReceiveLAPI(reclaim.Published{Value: client})` on a route that subscribes and has received nothing; mutation check: passing a nil hook in ReceiveLAPI fails the WARN test (2a196881).
   Quote:
      ```
      // pkg/bouncer/bouncer_leg_lapi.go:20 (production)
      func (b *Bouncer) ReceiveLAPI(published any) {
      	b.receiveBinding(&b.lapiLeg, published, func() string { return b.loadedLAPI().Incarnation() }, b.warnMissingStreamScopes)
      }
      // pkg/bouncer/zzz_servehttp_gaps_test.go:126 (test; was b.receiveLAPI() before this round)
      b.traceBinding(&b.lapiLeg, client.Incarnation(), b.warnMissingStreamScopes)
      b.traceBinding(&b.lapiLeg, client.Incarnation(), b.warnMissingStreamScopes)
      ```
2. [hard] Edge case untested — `pkg/admission/admission.go:88` — the utilities bump (backendbackoff v1.0.9 `Allow` lost its context) moved the finished-request early exit into `Gate.Admit`; no test calls `Admit` (or an AppSec/ModSec query) with a context that is already cancelled, so deleting the branch keeps every test green, and a cancelled request could then be admitted as the half-open probe while the leg backs off
   Fix: In `pkg/admission/zzz_admission_test.go`, call `Admit` with a cancelled context on a gate (also one backing off) and assert `context.Canceled`, a ticket that is not admitted, and that the next request still gets the probe
   Status: done
   Argument: Added TestGate_canceledRequestDoesNotTakeTheProbe (trip, cooldown elapsed, Admit with a canceled ctx returns context.Canceled and no admission, next request gets the probe); mutation check: removing the ctx.Err branch fails it (2a196881).
   Quote:
      ```
      // pkg/admission/admission.go:87 (production)
      // backendbackoff v1.0.9 dropped the context from Allow; keep the early exit on a finished request.
      if err := ctx.Err(); err != nil {
      	return Ticket{}, err
      }
      // tests grepped: pkg/admission/zzz_admission_test.go Admit(context.Background()) only;
      // appsec/modsecurity cancel tests cancel after the hop started (past Admit)
      ```
