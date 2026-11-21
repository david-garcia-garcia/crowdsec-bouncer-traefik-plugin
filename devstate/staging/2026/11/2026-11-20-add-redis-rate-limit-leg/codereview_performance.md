# Performance

1. [judgement] Hot-path body peek before the cheap policy check — `pkg/bouncer/bouncer_serve_ratelimit.go:51` — `serveRateLimit` calls `isCaptchaFormAnswer` (which buffers up to 64 KiB of every POST body via `peekCaptchaFormBody` and parses it with `url.ParseQuery` / multipart) before `answerRateLimitChallengeForm` checks `rateLimitAnswersWithCaptcha(client)`; on a rate-limit route with a usable captcha whose owner policy has no captcha bucket and no captcha failure action, every POST now pays the peek and parse for nothing, and the work grows with body size up to the `captchaFormMaxBytes` cap (bounded, so judgement, not hard)
   Fix: Gate the marker check on `rateLimitAnswersWithCaptcha(client)` (cheap field reads) before calling `isCaptchaFormAnswer`, keeping the current answer for policies that can challenge
   Status: skipped
   Argument: judgement; bounded by the 64 KiB cap. The reorder changes which POSTs skip the buckets (marker POST on a policy without a captcha answer), the same decision Security 1 raises, so it waits for the human: issues.md note `knowledge/debt/2026-11-21-rate-limit-marker-post-uncharged-without-gate.md`.
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
