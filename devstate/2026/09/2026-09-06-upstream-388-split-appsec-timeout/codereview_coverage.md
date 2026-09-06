# Test coverage

1. [hard] Critical path untested — `pkg/lapi/client.go:169` — `http.Client.Timeout` retargeted to `configuration.EffectiveLapiHTTPTimeout(config)`; `Test_EffectiveHTTPTimeouts` in `pkg/configuration/configuration_test.go:183-209` only asserts the helper, and `TestIdentityHex_EffectiveLapiTimeout` in `pkg/lapi/session_test.go:74-93` covers identity hashing only — reverting this line to `time.Duration(config.HTTPTimeoutSeconds) * time.Second` leaves all tests green while `crowdsecLapiHttpTimeoutSeconds` overrides would be ignored on the wire
   → Assert `lapi.New` builds a client whose `http.Client.Timeout` matches `EffectiveLapiHTTPTimeout` (or a hanging httptest LAPI call with a short override finishes well under `HTTPTimeoutSeconds`)
   Status: open
   Argument: none.

2. [hard] Critical path untested — `pkg/bouncer/bouncer.go:90` — captcha siteverify `http.Client.Timeout` retargeted to `configuration.EffectiveCaptchaSiteverifyHTTPTimeout(config)`; `Test_EffectiveHTTPTimeouts` in `pkg/configuration/configuration_test.go:183-209` asserts the helper only — `(none)` in bouncer or captcha tests inspects the wired client, so reverting to `HTTPTimeoutSeconds` stays green
   → Assert `bouncer.New` passes a siteverify client whose `Timeout` equals `EffectiveCaptchaSiteverifyHTTPTimeout`, or exercise a slow siteverify mock and show the override deadline is honored
   Status: open
   Argument: none.
