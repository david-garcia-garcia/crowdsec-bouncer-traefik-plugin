# Performance

1. [judgement] Hot-path body peek before the cheap policy check — `pkg/bouncer/bouncer_serve_ratelimit.go:51` — `serveRateLimit` calls `isCaptchaFormAnswer` (which buffers up to 64 KiB of every POST body via `peekCaptchaFormBody` and parses it with `url.ParseQuery` / multipart) before `answerRateLimitChallengeForm` checks `rateLimitAnswersWithCaptcha(client)`; on a rate-limit route with a usable captcha whose owner policy has no captcha bucket and no captcha failure action, every POST now pays the peek and parse for nothing, and the work grows with body size up to the `captchaFormMaxBytes` cap (bounded, so judgement, not hard)
   Fix: Gate the marker check on `rateLimitAnswersWithCaptcha(client)` (cheap field reads) before calling `isCaptchaFormAnswer`, keeping the current answer for policies that can challenge
   Status: done
   Argument: e4e19906 (with Security 1, human decision 2026-11-22): `isRateLimitChallengeFormAnswer` checks the usable captcha, `rateLimitAnswersWithCaptcha`, and `match.BypassCaptchaName` before `HasChallengeMarker`; a unit test proves the body is not read when the policy has no captcha answer or a `bypassCaptcha` rule matched.
   Quote:
   ```
   captchaClient := b.usableCaptcha()
   ...
   if b.isCaptchaFormAnswer(req) {
       logger.Trace(b.log, "serveRateLimit", "ip", req.IPAddrString(), "captchaForm", true)
       return b.answerRateLimitChallengeForm(rw, req, match, client)
   }
   ```
   Note:
   ```
   Checked and not filed: Charge now keeps walking past a captcha bucket over its limit, so more Take
   round trips per request, but the walk is over the owner's configured bucket list (fixed at Open) under
   one StepBudget context; captchaClient.Check is an HMAC check with no I/O; logger.Debounced is keyed by
   the constant message; OwnershipKey json.Marshal of the bucket rows, the leg table loops and
   traceBinding run only at constructor / publish time over five fixed legs.
   ```
