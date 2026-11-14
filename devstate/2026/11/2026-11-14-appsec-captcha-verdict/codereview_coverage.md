# Test coverage

1. [hard] Edge case untested — `pkg/bouncer/bouncer.go:324` — `hasUsableCaptcha` special-cases a subscribed but unpublished or invalid captcha client (spec: "subscribed, published, Valid"); no test drives a marker POST that AppSec allowed on such a router, so reducing it to `return b.subscribeCaptcha` (marker POST becomes a downgrade ban instead of reaching origin) stays green
   Quote:
   ```
   captchaClient := b.loadedCaptcha()
   return captchaClient != nil && captchaClient.Valid
   // tests: TestAppsecCaptchaVerdict_markerPostWithoutRouterCaptchaReachesOrigin uses bindTestCaptcha(b, nil) -> subscribeCaptcha=false only; subscribed+nil/invalid arm: (none)
   ```
   Fix: Add a test with `subscribeCaptcha = true` and a nil (or `Valid == false`) captcha client where AppSec allows a `crowdsec_captcha_challenge=v1` POST; assert the backend receives it with the body unchanged and no ban is written
   Status: done
   Argument: Added `TestAppsecCaptchaVerdict_markerPostWithUnusableCaptchaReachesOrigin` (subscribed+unpublished, subscribed+!Valid): backend gets the body, no header.
2. [judgement] Assertion does not prove the job — `pkg/bouncer/bouncer.go:418` — `handleCaptchaKindServeHTTP` now takes the downgrade ban reason from its caller; the LAPI caller's `ReasonLAPI` is asserted by no test (unsubscribed/unpublished LAPI tests check only 403 and the WARN line), so passing the wrong template reason on an LAPI captcha downgrade stays green
   Quote:
   ```
   return b.handleCaptchaKindServeHTTP(rw, req, origin, headerReasonFromOrigin(origin), configuration.ReasonLAPI)
   // tests: TestHandleRemediationServeHTTP_unsubscribedCaptchaWarnsThenBans, _subscribedUnpublishedDoesNotWarnUnsubscribed assert status/log, not RemediationReason
   ```
   Fix: In an existing LAPI captcha downgrade test, use a ban template with `{{.RemediationReason}}` and assert `LAPI` in the body
   Status: done
   Argument: Added `TestLapiCaptchaDowngrade_keepsLapiBanReason` asserting `reason=LAPI` and `ban:captcha-downgrade`.
