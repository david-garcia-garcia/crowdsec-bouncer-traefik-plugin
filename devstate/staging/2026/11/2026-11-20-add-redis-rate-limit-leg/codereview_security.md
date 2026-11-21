# Security

1. [judgement] Client-controlled trust — `pkg/bouncer/bouncer_serve_ratelimit.go:51` — a POST carrying `crowdsec_captcha_challenge=v1` skips every bucket even when no captcha gate will answer it, so it reaches the application uncharged
   Fix: Skip the buckets for a marker POST only when a captcha gate on this router will answer it; when `answerRateLimitChallengeForm` declines (a `bypassCaptcha` rule matched, or a policy without a captcha answer on a router with no AppSec step and no `captcha` rule for the request), charge it like any other request
   Status: skipped
   Argument: judgement; changes the human-decided exemption for captcha-page traffic (decision 5) and the spec line "Otherwise the POST SHALL continue to the AppSec step". Needs a human decision; recorded as issues.md note `knowledge/debt/2026-11-21-rate-limit-marker-post-uncharged-without-gate.md`.
   Quote:
   ```go
   if b.isCaptchaFormAnswer(req) {
   	logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "captchaForm", true)
   	return b.answerRateLimitChallengeForm(rw, req, match, client)
   }
   ```
   Note:
   ```
   Source: the request body field (client). Sink: the bucket skip in serveRateLimit, then next.
   Reachable whenever the router has a usable captcha (for example only to serve LAPI captcha decisions):
   - Policy with only `ratelimit` buckets, router without an AppSec subscription: answerRateLimitChallengeForm
     returns false at line 96, serveAppSec writes nothing, and the POST reaches origin with its body intact
     (HasChallengeMarker does not consume it). Adding `&crowdsec_captcha_challenge=v1` to a form-encoded
     login POST therefore disables a brute-force `ratelimit` bucket on POST /login.
   - Any policy when a `bypassCaptcha` rule matches: line 96 returns false, serveAppsecCaptchaGate also
     returns false on the bypass, and the POST reaches origin uncharged, although the README says a
     bypassCaptcha request "get[s] the ratelimit answer of the captcha bucket instead ... so the limit still holds".
   Distinct from the recorded follow-up 2026-11-21-rate-limit-captcha-marker-flood: that note's risk is a
   siteverify flood while the gate answers each marker POST; here no gate answers and the protected
   application endpoint itself is reached without being counted. The spec line "Otherwise the POST SHALL
   continue to the AppSec step" permits it, hence judgement, not hard.
   ```
2. [judgement] Fail-open on deny — `pkg/bouncer/bouncer_serve_ratelimit.go:41` — a subscriber whose `rateLimitInstanceName` no owner publishes lets every request through with only a TRACE `crowdsec bouncer unbound` line, so a typo or a removed owner silently disables the limit
   Fix: Keep the documented passthrough, but log a debounced WARN (as `logRateLimitCaptchaDowngrade` does with `logger.Debounced`) when a subscribed router serves a request with no bound rate-limit client
   Status: skipped
   Argument: judgement; the passthrough is the documented contract (spec "Missing rate-limit client charges nothing", README). A request-time WARN is new behaviour; recorded as issues.md note `knowledge/debt/2026-11-21-rate-limit-unpublished-owner-warn.md`.
   Note:
   ```
   New in round 2: round 1 opened the counter on the router itself, so there was no unpublished-owner path.
   Spec "Missing rate-limit client charges nothing" and README "When the policy is not loaded" document the
   passthrough, so this is not hard; the gap is that nothing above TRACE tells the operator, whereas the
   other legs apply a failure action and an unsubscribed captcha logs WARN or ERROR.
   ```
