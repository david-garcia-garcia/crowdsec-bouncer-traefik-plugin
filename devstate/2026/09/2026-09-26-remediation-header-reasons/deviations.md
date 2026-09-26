# Deviations

- [x] taken  captcha challenge page does not own the structured header value
  Asked: Ground names `pkg/captcha/captcha.go` `writeRemediationHeader(..., "captcha")` on the challenge page, so captcha would have to know `captcha:lapi[:origin]` / `captcha:decision-header` / failure reasons.
  Instead: `ServeHTTP` takes the already-formatted challenge-page value from the Bouncer; captcha only writes `captcha:solved` on Pass 302 and `WriteSolvedRedirect`.
  Owner: `pkg/captcha/captcha.go` `writeRemediationHeader`
  Why: honouring captcha-owned origin mapping would add `MetricsOrigin` / `OriginPlugin*` to a Client whose job is widget and verify; the header name was already lifted off Client for that reason (`core_plugin_middleware_bouncer`).
  By: explore
  Requester: not asked
