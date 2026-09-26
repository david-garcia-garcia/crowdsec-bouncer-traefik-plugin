# Test coverage

1. [hard] Edge case untested — `pkg/bouncer/bouncer.go:458` — GetRemoteIP error and nil IP pass `headerReasonUnparseableRequest`; `TestServeHTTP_BadRemoteAddrBans` and `TestServeHTTP_UnparseableClientIPBans` assert 403 only
   Quote:
      ```
      b.handleBanServeHTTP(rw, req, configuration.ReasonTECH, headerReasonUnparseableRequest, lapi.OriginPluginTechGetRemoteFail)
      if *passed || rw.Code != http.StatusForbidden {
      TestHeaderReasonFromOrigin maps the origins; those ServeHTTP tests do not set remediationCustomHeader. (none)
      ```
   Fix: Assert `ban:unparseable-request` on GetRemoteIP error and nil IP when the header name is set
   Status: done
   Argument: Asserted ban:unparseable-request on TestServeHTTP_BadRemoteAddrBans and TestServeHTTP_UnparseableClientIPBans when the header name is set.
2. [hard] Critical path untested — `pkg/bouncer/bouncer.go:514` — cache lookup error that is not Redis-unreachable pass writes `headerReasonCacheFail`; no ServeHTTP test asserts `ban:cache-fail`
   Quote:
      ```
      b.banOrWarnForcedCaptcha(rw, req, configuration.ReasonTECH, headerReasonCacheFail, lapi.OriginPluginTechCacheFail)
      TestHeaderReasonFromOrigin / TestFormatRemediationHeader "closed reason never takes origin". (none)
      ```
   Fix: Assert a cache lookup error with the header name set returns `ban:cache-fail`
   Status: done
   Argument: Asserted ban:cache-fail on TestServeHTTP_RedisUnreachableFailureAction when BouncerRedisUnreachableBlock and the header name are set.
3. [hard] Critical path untested — `pkg/bouncer/bouncer.go:568` — fail-closed ban uses `headerReasonFromOrigin`; `TestServeHTTP_UnboundLAPIUsesFailureAction` and `TestServeHTTP_StreamUnhealthyUsesFailureAction` assert 403 only
   Quote:
      ```
      b.banOrWarnForcedCaptcha(rw, req, banReason, headerReasonFromOrigin(origin), origin)
      if *passed || rw.Code != http.StatusForbidden {
      TestServeHTTP_LiveCaptchaFailureAction asserts captcha:lapi-failure, not the ban arm.
      ```
   Fix: Assert `ban:lapi-failure` and `ban:stream-unhealthy` on those fail-closed ban paths when the header name is set
   Status: done
   Argument: Asserted ban:lapi-failure and ban:stream-unhealthy on those fail-closed ban subtests when the header name is set.
4. [hard] Critical path untested — `pkg/bouncer/bouncer.go:479` — forced `b` remediates with `OriginPluginForcedDecision`; `TestServeHTTP_forcedDecisionBanSkipsStream` asserts 403 and dropped metrics, not the header
   Quote:
      ```
      b.handleRemediationServeHTTP(rw, req, decisionscope.BannedValue, lapi.OriginPluginForcedDecision)
      if rw.Code != http.StatusForbidden || !strings.Contains(rw.Body.String(), "banned") {
      TestNew_CaptchaOwnerServesChallenge asserts captcha:decision-header, not ban:decision-header.
      ```
   Fix: Assert `ban:decision-header` when the remediation header name is set and the forced header is `b`
   Status: done
   Argument: Asserted ban:decision-header on TestServeHTTP_forcedDecisionBanSkipsStream when the header name is set.
5. [hard] Critical path untested — `pkg/captcha/captcha.go:113` — Pass 302 writes `captcha:solved`; `Test_ServeHTTP_dummyProviderSolveIssuesGateCookie` passes an empty header name
   Quote:
      ```
      writeRemediationHeader(rw, remediationHeader, remediationHeaderCaptchaSolved)
      client.ServeHTTP(solveRW, solveReq, "1.2.3.4", "", "")
      Test_WriteSolvedRedirect_noCookieRemint asserts captcha:solved on WriteSolvedRedirect only.
      ```
   Fix: Assert Pass 302 sets `captcha:solved` when the remediation header name is configured
   Status: done
   Argument: Pass 302 now passes X-Remediation and asserts captcha:solved in Test_ServeHTTP_dummyProviderSolveIssuesGateCookie.
