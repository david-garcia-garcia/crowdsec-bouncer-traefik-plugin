# Deviations

- [x] taken  the WAF legs receive the per-request read-deadline control as a parameter
  Asked: a total read deadline on bodies of unknown length, implemented once in `pkg/wafhop` for both legs, that blocks independently of the failure action (decisions 1 and 2); no criterion names a signature change.
  Instead: `appsec.Client.Query(req, pol, dl)` gains a third parameter and `modsecurity.Client.Inspect(req, dl)` replaces its `failureAction` parameter (used only by the removed drop branch). `dl` is a narrow `wafhop.ReadDeadliner` the bouncer builds from `rw` with `http.NewResponseController`. Call sites migrated here: `Query` 1 production + 69 test, `Inspect` 1 production + 5 test (explore.md, Call sites).
  Owner: `pkg/bouncer` (sole owner of `rw`); `pkg/wafhop/body.go` (`ReadBody`, owner of the read and the deadline)
  Why: the response writer is the only handle that sets a read deadline on HTTP/1.1 (`Body.Close` cannot cut it, #204 measurement); the bouncer owns it and the shared read owns the cut. Rank `bounded incidental` (explore.md, open question on how the control reaches `pkg/wafhop`).
  By: explore
  Requester: not asked
- [x] taken  `wafhop.ReadBody` loses its "limit 0 or less = no cap" mode
  Asked: `appsecBodyLimit` values `<= 0` become 10 MiB; `modsecBodyLimit` keeps `>= 1` (decision 4). No criterion names the shared reader's contract.
  Instead: with both callers always passing a positive limit, the no-cap branches in `ReadBody` / `bufferBody` are removed and a non-positive limit is documented as a caller bug; the `math.MaxInt64` overflow guard stays.
  Owner: `pkg/wafhop/body.go` (`ReadBody`, `bufferBody`)
  Why: after decision 4 the mode has no caller; keeping it is dead code and keeps an unbounded buffer path reachable by a future caller. Rank `bounded asked` on the parent decision; this part is incidental to it (explore.md, open question on `appsecBodyLimit <= 0`).
  By: explore
  Requester: not asked
- [x] taken  the read-deadline control is the concrete `*http.ResponseController`, not the `wafhop.ReadDeadliner` interface
  Asked: no criterion names the type; the explore row above and design D2/D4 chose a narrow interface `wafhop.ReadDeadliner` so tests could pass a stub.
  Instead: `wafhop.ReadBody(httpReq, limit, mode, ctrl *http.ResponseController, timeout)`, `appsec.Client.Query(req, pol, ctrl)`, and `modsecurity.Client.Inspect(req, ctrl)` take the concrete controller. Tests pass `nil` (the `Close` fallback), a controller on an `httptest.ResponseRecorder` (its `SetReadDeadline` fails, so the fallback runs), or a real `httptest` server; the stub-controller unit test is replaced by those.
  Owner: `pkg/wafhop/body.go` (`ReadBody`, `cutBodyRead`)
  Why: measured under Yaegi v0.16.1 (the interpreter Traefik loads the plugin with): a `nil` comparison of an interpreted interface holding the native controller panics in the `time.AfterFunc` goroutine, and capturing it in the callback closure panics with `reflect.Value.Set using unaddressable value`; the concrete pointer runs (`pkg/wafhop/zzz_yaegi_body_read_deadline_test.go`). The job (one shared read that the bouncer's controller can cut) is unchanged.
  By: implement
  Requester: not asked
