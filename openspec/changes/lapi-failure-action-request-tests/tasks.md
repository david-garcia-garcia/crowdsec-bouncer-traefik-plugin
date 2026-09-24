## 1. Stream poll failure

- [ ] 1.1 Add a test that `New`s stream mode against an httptest LAPI returning 500 on the stream route, waits until `StreamHealthy` is false, then `ServeHTTP` with `bouncerLapiFailureAction` `passthrough` (next is called, status 200) and `ban` (next is not called, ban status). Do not call `SetStreamHealthyForTest`.

## 2. LAPI captcha challenge

- [ ] 2.1 Add a test that `New`s live mode against an httptest LAPI returning 500, with `bouncerLapiFailureAction` `captcha` and a captcha template, then `ServeHTTP` asserts `X-Remediation: captcha` and the challenge page marker.
