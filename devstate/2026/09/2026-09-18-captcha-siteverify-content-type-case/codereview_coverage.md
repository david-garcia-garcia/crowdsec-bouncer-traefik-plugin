# Test coverage

1. [hard] Edge case untested — `pkg/captcha/captcha.go:325` — spec MUST NOT treat `application/jsonp` as JSON; dest `HasPrefix` would; no test fails if that equals-token check is reverted
   → Assert `application/jsonp` + `{"success":true}` is 200 with no `crowdsec_captcha_gate`
   Status: done
   Argument: added Test_ServeHTTP_jsonpSiteverifyContentTypeIsNotJSON in pkg/captcha/zzz_servehttp_test.go (6eb1b04).
