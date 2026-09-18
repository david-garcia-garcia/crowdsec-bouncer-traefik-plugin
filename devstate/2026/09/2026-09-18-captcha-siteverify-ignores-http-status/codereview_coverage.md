# Test coverage

1. [judgement] Happy path only — `pkg/captcha/captcha.go:325` — spec scenario Status 201 with success JSON is a solve has no test; dest `Test_ServeHTTP_dummyProviderSolveIssuesGateCookie` already asserts the 200 success arm
   → Add a 201 stub that asserts 302 + `crowdsec_captcha_gate`, or skip if the 200 solve test already proves the 2xx success arm
   Status: skipped
   Argument: judgement; dest 200 solve test already proves the 2xx success arm; 201 is not a new reject path.
