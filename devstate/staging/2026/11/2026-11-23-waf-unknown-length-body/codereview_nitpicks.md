# Nitpicks

1. [hard] Name for the scope — `pkg/appsec/zzz_test_helpers.go:111` — the helper renamed in this diff, `newUnknownLengthGetRequest`, is test-only but has no "Test" in its name, and this file is not a `_test.go` file, so it compiles into the plugin. The name also leaves out that the body never ends (`blockingBody`), which is the reason it exists. Its new sibling `newUnknownLengthTestRequest` (finite body) differs from it only by `Get`/`Test`.
   Quote:
   ```go
   // newUnknownLengthGetRequest is an HTTP/3 GET whose body never ends: AppSec must not read it.
   func newUnknownLengthGetRequest(done <-chan struct{}) *http.Request {
   	req, _ := http.NewRequest(http.MethodGet, "http://localhost/", blockingBody{done: done})
   ```
   Fix: Rename to `newStalledUnknownLengthGetTestRequest` (or similar) and update its one caller in `zzz_unknown_length_body_test.go`
   Status: done
   Argument: Renamed to `newStalledUnknownLengthGetTestRequest` (definition and its one caller); the helpers file is now `zzz_test_helpers_test.go`, so it no longer compiles into the plugin.
2. [hard] Name for the scope — `pkg/wafhop/zzz_yaegi_body_read_deadline_test.go:53` — in the interpreted program, the helper that writes to stderr and exits 1 is named `fail`, a vague verb. The sibling Yaegi programs in this repo (`pkg/bouncer/zzz_yaegi_leg_binding_test.go`, `pkg/ratelimit/zzz_yaegi_test.go`) name the same job `exitWithFailure`.
   Quote:
   ```go
   func fail(format string, args ...interface{}) {
   	fmt.Fprintf(os.Stderr, format+"\n", args...)
   	os.Exit(1)
   }
   ```
   Fix: Rename to `exitWithFailure` (keeping the format arguments) at the definition and its five call sites in the program string
   Status: done
   Argument: Renamed the Yaegi program's `fail` to `exitWithFailure` at the definition and all call sites, matching the sibling Yaegi programs.
3. [judgement] Linear coding — `pkg/wafhop/body.go:125` — `bufferBody` now does three jobs in one body: reuse an earlier buffer, read under the deadline, and put the replay back on the request. The deadline read (start the timer, read, `!timer.Stop()`) is a separate, self-contained job written inline, and `buf.ReadFrom(reader)` appears in both branches.
   Quote:
   ```go
   if httpReq.ContentLength < 0 {
   	timer := time.AfterFunc(timeout, func() { cutBodyRead(ctrl, src) })
   	_, err = buf.ReadFrom(reader)
   	// Stop reports false once the callback has run (or is running): the deadline fired.
   	timedOut = !timer.Stop()
   } else {
   	_, err = buf.ReadFrom(reader)
   }
   ```
   Fix: Move the block into a helper named for its job, for example `readWithinDeadline(buf, reader, src, ctrl, timeout) (timedOut bool, err error)`, with an early return for a declared length; `bufferBody` calls it. This must still run under Yaegi (see deviations: the concrete `ctrl` is captured in the closure)
   Status: skipped
   Argument: Judgement: the inline timer block is the shape measured under Yaegi v0.16.1 (deviations row 3, closure capture of the concrete controller); moving it into a helper re-opens that risk for readability only.
4. [judgement] Clear conditions — `pkg/wafhop/body.go:155` — the fallback condition runs the main action (`SetReadDeadline`) inside an `||` that has a negation on each side. To see that the deadline is set first and `Close` is only the fallback, the reader has to work through the short-circuit.
   Quote:
   ```go
   if ctrl == nil || ctrl.SetReadDeadline(time.Now()) != nil {
   	_ = body.Close()
   }
   ```
   Fix: `if ctrl != nil && ctrl.SetReadDeadline(time.Now()) == nil { return }` then `_ = body.Close()`, or name the attempt (`cutThroughController(ctrl) bool`). The behaviour stays the same; check the result under the Yaegi test
   Status: skipped
   Argument: Judgement: behaviour-neutral style on the Yaegi-measured callback; not applied unattended.
5. [judgement] Linear coding — `pkg/appsec/query.go:259` — this diff removed the unreadable-body case, which leaves `newAppsecBodyRequest` as a `switch` with one `case` plus `default`. The main path (POST with the copied body) is nested inside the case, and the headers-only GET sits in `default` at the bottom.
   Quote:
   ```go
   switch {
   case wafhop.HasBody(httpReq) && isMethodWithForwardableBody(httpReq.Method):
   	// ... ReadBody, build POST ...
   	return req, nil
   default:
   	req, _ := http.NewRequest(http.MethodGet, target, nil)
   	return req, nil
   }
   ```
   Fix: Add a guard clause: `if !wafhop.HasBody(httpReq) || !isMethodWithForwardableBody(httpReq.Method) { return GET }`, then the POST path at the left margin
   Status: skipped
   Argument: Judgement: behaviour-neutral restructure of `newAppsecBodyRequest`; the switch reads correctly and the diff stays minimal.
6. [judgement] Symmetry and consistency — `pkg/bouncer/bouncer_serve_waf.go:45` — the two sibling answer helpers in this file take only `leg` and keep their own log text. `handleBodyReadTimeoutServeHTTP` instead takes `leg` and also a `warning` that has to match that leg, so every caller passes the pair (`legAppsec, msgAppsecBodyReadTimeout` / `legModsec, msgModsecBodyReadTimeout`) and nothing in the code keeps the two in step.
   Fix: Choose the message from `leg` inside the helper (for example a `bodyReadTimeoutWarning(leg)` lookup) so callers pass `leg` only, the same way as the siblings. Or, if passing both stays, record why
   Status: skipped
   Argument: Judgement: the pairing is explicit at the two call sites and each message constant names its leg; not applied unattended.
7. [judgement] Clear conditions — `tests/e2e/real/TestUtils.ps1:366` — in `Invoke-H2cUnknownLengthRequest`, `$answeredMs = -1` is a "not measured yet" placeholder value, and `if ($answeredMs -lt 0)` is the complement of that value rather than the actual case (no stall, or Traefik did not answer during the stall). The stall handling is also split across three `$StallSeconds` checks (lines 349, 357, and the placeholder at 366).
   Fix: Name the case with a boolean (`$answeredDuringStall`) that the stall block sets with the elapsed time it measured, then `if (-not $answeredDuringStall) { $answeredMs = $watch.ElapsedMilliseconds }` after `GetResult`
   Status: skipped
   Argument: Judgement: e2e helper style; the h2c cases pass in CI as written. Not applied unattended.
