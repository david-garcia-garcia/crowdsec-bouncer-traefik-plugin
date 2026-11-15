# Nitpicks

1. [hard] Symmetry and consistency — `pkg/bouncer/bouncer.go:433` — `handleCaptchaKindServeHTTP(rw, req, origin, headerReason, banReason string)` takes the same three string roles as its sibling `handleBanServeHTTP(rw, req, reason, headerReason, origin string)` (and `banWarnCaptchaRule`) in reverse order, so the new call sites read `handleCaptchaKindServeHTTP(rw, req, originAppsec, headerReasonAppsec, configuration.ReasonAPPSEC)` next to `handleBanServeHTTP(rw, req, configuration.ReasonAPPSEC, headerReasonAppsec, originAppsec)`; three untyped strings in opposite order can be swapped silently
   Quote:
   ```
   func (b *Bouncer) handleCaptchaKindServeHTTP(rw http.ResponseWriter, req clientrequest.Request, origin, headerReason, banReason string) bool {
   ...
   func (b *Bouncer) handleBanServeHTTP(rw http.ResponseWriter, req clientrequest.Request, reason, headerReason, origin string) {
   ```
   Fix: Order the new parameters as the ban sibling does, `(rw, req, banReason, headerReason, origin string)`, and update the two callers (`handleRemediationServeHTTP`, `serveAppsecCaptchaGate`) to match
   Status: done
   Argument: `handleCaptchaKindServeHTTP` now takes `(banReason, headerReason, origin)`, the `handleBanServeHTTP` order; both callers updated.
2. [hard] Linear coding — `pkg/bouncer/bouncer.go:312` — `serveAppSec` re-derives one decision ("a captcha form answer this router can validate") from two clauses at the call site, and the second clause calls `b.loadedCaptcha()` again on the assumption that `hasUsableCaptcha()` nil-checked a separate load; the reader must open `hasUsableCaptcha` to see why `.HasChallengeMarker` cannot dereference nil
   Quote:
   ```
   if b.hasUsableCaptcha() && b.loadedCaptcha().HasChallengeMarker(req.Request) {
       return b.serveAppsecCaptchaGate(rw, req)
   }
   ```
   Fix: Ask one predicate named for the concept (e.g. `b.isCaptchaFormAnswer(req)`) that loads the captcha client once, returns false early when unsubscribed, nil, or invalid, then returns `captchaClient.HasChallengeMarker(req.Request)`; `serveAppSec` calls that name
   Status: done
   Argument: `serveAppSec` calls `isCaptchaFormAnswer(req)`, which loads the client once through `usableCaptcha()`.
3. [judgement] Name for the scope — `pkg/bouncer/zzz_appsec_captcha_verdict_test.go:41` — the local `origin` (and the returned `*appsecVerdictOrigin`) is the backend recorder, while in this package and in the same test bodies `origin` is the usage-metrics origin (`originAppsec`, `TestDroppedCount("appsec", ...)`); the type comment itself says "records what reached the backend"
   Quote:
   ```
   origin := &appsecVerdictOrigin{}
   ...
   if origin.called {
   ...
   if got := lapiClient.TestDroppedCount("appsec", "ipv4", "captcha"); got != 1 {
   ```
   Fix: Name the local for its role in these bodies, `backend` (`backend.called`, `backend.body`), across `testAppsecVerdictBouncer` and its callers
   Status: done
   Argument: The recorder local is `next` (type `recordedNextRequest`); test messages say "the backend".
