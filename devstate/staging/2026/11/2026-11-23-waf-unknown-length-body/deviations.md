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
