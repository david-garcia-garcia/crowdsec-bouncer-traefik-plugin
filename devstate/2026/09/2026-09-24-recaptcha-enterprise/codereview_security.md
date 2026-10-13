# Security

1. [judgement] Download integrity — `pkg/captcha/assessments.go:94` — assessments `http.Client` has no host-bound CheckRedirect, so a cross-host 3xx copies `X-Goog-Api-Key` and a forged Assessment could Pass; reachability unknown (needs googleapis.com to redirect)
   Fix: Reject redirects whose host is not recaptchaenterprise.googleapis.com
   Status: skipped
   Argument: judgement; reachability unknown.
