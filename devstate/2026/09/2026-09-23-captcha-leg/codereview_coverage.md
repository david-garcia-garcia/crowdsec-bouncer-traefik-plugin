# Test coverage

1. [hard] Critical path untested — `pkg/bouncer/bouncer.go:387` — unpublished subscribed captcha with startup block on returns 503; no test fails if that branch is reverted
   Quote:
      ```
      if b.subscribeCaptcha && b.loadedCaptcha() == nil {
          rw.WriteHeader(http.StatusServiceUnavailable)
          return
      }
      TestNew_CaptchaSubscriberBeforePublishBans sets BouncerStartupBlock=false and asserts 403; getTestConfig leaves startupBlock zero. (none) for 503
      ```
   Fix: Assert ServeHTTP returns 503 when the bouncer subscribed to captcha, startupBlock is true, and the captcha binding is empty
   Status: done
   Argument: Added TestNew_CaptchaSubscriberBeforePublishBlocks (503 when startupBlock and captcha unbound).
2. [hard] Critical path untested — `pkg/bouncer/bouncer.go:614` — subscriber challenge must write this router's header, not the owner's; no test fails if the header is stored on the shared client again
   Quote:
      ```
      captchaClient.ServeHTTP(rw, req.Request, req.remoteIP, b.remediationCustomHeader)
      TestNew_CaptchaOwnerOmitFillsTraefikName uses X-Remediation on owner and subscriber and does not assert the header; Test_WriteSolvedRedirect asserts the passed name on a unit Client
      ```
   Fix: Assert a subscriber challenge writes X-Route and not the owner's X-Owner
   Status: done
   Argument: Added TestNew_CaptchaSubscriberUsesRouterHeader (X-Route captcha, no X-Owner).
