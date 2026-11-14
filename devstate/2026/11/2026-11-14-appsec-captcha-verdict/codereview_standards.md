# Standards

1. [hard] Name for the scope — `pkg/bouncer/zzz_appsec_captcha_verdict_test.go:23` — type `appsecVerdictOrigin` records whether the backend (`b.next`) was called and its body, but in `pkg/bouncer` "origin" is the usage-metrics origin (`originAppsec`, the `origin` parameter of `handleCaptchaKindServeHTTP`, `TestDroppedCount("appsec", …)` in the same tests), so the name reads as "the metrics origin of an AppSec verdict"; sibling tests in the package call this role `next` (`nextCalled`)
   Fix: Rename the type to the backend role (`recordedNextRequest` or similar) and its locals from `origin` to `next`, so `origin` keeps meaning only the metrics origin in this package
   Status: done
   Argument: Type renamed to `recordedNextRequest`, locals to `next`.
   Quote:
   ```
   // appsecVerdictOrigin records what reached the backend.
   type appsecVerdictOrigin struct {
   ```
2. [hard] Consume before produce — `pkg/bouncer/zzz_appsec_captcha_verdict_test.go:92` — new `hasGateCookie` walks `rw.Result().Cookies()` by name, which `cookieNamed(cookies, name)` in `pkg/bouncer/zzz_dual_cookie_secure_test.go:52` (same package) already does
   Fix: Delete `hasGateCookie`; at each call site use `cookie := cookieNamed(rw.Result().Cookies(), "crowdsec_captcha_gate")` and check `cookie != nil && cookie.Value != ""`
   Status: done
   Argument: `hasGateCookie` now delegates to `cookieNamed` from `zzz_dual_cookie_secure_test.go`.
   Quote:
   ```
   func hasGateCookie(rw *httptest.ResponseRecorder) bool {
   	for _, cookie := range rw.Result().Cookies() {
   		if cookie.Name == "crowdsec_captcha_gate" && cookie.Value != "" {
   ```
3. [hard] Leave a trail — `pkg/bouncer/zzz_appsec_captcha_verdict_test.go:64` — new helpers `appsecAnswers` (line 64) and `captchaFormPost` (line 82) have no job comment, while their siblings in the same file (`testAppsecVerdictBouncer`, `testSiteverifyCaptchaClient`) do
   Fix: Add one line each, e.g. `// appsecAnswers is an AppSec stand-in that answers every query with status and body.` and `// captchaFormPost builds a form-encoded POST to /protected, with the gate cookie when gateCookie is set.`
   Status: done
   Argument: Job comments added to `appsecAnswers` and `captchaFormPost`.
4. [judgement] Duplicated Code — `pkg/bouncer/bouncer.go:319` — new `hasUsableCaptcha` restates the usable-client guard that `handleCaptchaKindServeHTTP` already holds (`!b.subscribeCaptcha`, then `captchaClient == nil || !captchaClient.Valid` at lines 434-443), and `serveAppSec` then loads the client a second time (`b.loadedCaptcha().HasChallengeMarker`) before `serveAppsecCaptchaGate` loads and checks it a third time; a change to what "usable" means must now be made in two places
   Fix: Let `hasUsableCaptcha` own the check and return the loaded client (`usableCaptcha() *captcha.Client`, nil when unsubscribed or not Valid); use it in `serveAppSec` and for the nil/`!Valid` branch of `handleCaptchaKindServeHTTP`, keeping the unsubscribed WARN there
   Status: done
   Argument: `usableCaptcha()` owns the subscribed/published/Valid check; `isCaptchaFormAnswer` and the nil/!Valid branch of `handleCaptchaKindServeHTTP` use it.
   Quote:
   ```
   if b.hasUsableCaptcha() && b.loadedCaptcha().HasChallengeMarker(req.Request) {
   ```
5. [judgement] Data Clumps — `pkg/bouncer/bouncer.go:433` — the change grows `handleCaptchaKindServeHTTP` to three adjacent strings (`origin, headerReason, banReason`), the same trio `handleBanServeHTTP(rw, req, reason, headerReason, origin)` at line 351 takes in the opposite order; two same-typed string lists with inverted order across call sites make a swapped argument compile silently
   Fix: At minimum, order the new parameters as `handleBanServeHTTP` does (`banReason, headerReason, origin`); if the trio keeps spreading, give it one small type whose fields are only template reason, header reason, and metrics origin
   Status: done
   Argument: Parameters reordered to match `handleBanServeHTTP`; no new type, the trio has two callers.
   Quote:
   ```
   func (b *Bouncer) handleCaptchaKindServeHTTP(rw http.ResponseWriter, req clientrequest.Request, origin, headerReason, banReason string) bool {
   ```
