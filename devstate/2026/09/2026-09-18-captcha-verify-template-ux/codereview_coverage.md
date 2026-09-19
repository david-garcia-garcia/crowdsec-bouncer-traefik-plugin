# Test coverage

1. [hard] Edge case untested — `pkg/captcha/captcha.go:320` — custom+json marshals `siteverifyRequest.RemoteIP`; `Test_ServeHTTP_siteverifyPostsRemoteIP` captures form encoding; `Test_Validate_customJSONPostsJSONSecretAndResponse` calls `Validate(..., "")` and only asserts omit; reverting the JSON field leaves those tests green
   → Assert custom+json siteverify JSON includes `"remoteip"` equal to a non-empty `Validate`/`ServeHTTP` remoteIP
   Status: open
   Argument: none.
