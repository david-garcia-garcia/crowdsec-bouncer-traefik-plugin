## 1. Validate media-type match

- [ ] 1.1 In `Client.Validate`, parse siteverify `Content-Type` with `mime.ParseMediaType` and treat the body as JSON only when the type token equals `application/json`. Parse error or any other type keeps `responseType:noJson` and `(false, nil)`.

## 2. Regression

- [ ] 2.1 Add a `zzz_*_test.go` under `pkg/captcha/` (existing `zzz_servehttp_test.go` or a new `zzz_` file) named `TestHunt_siteverifyJSONContentTypeIsCaseInsensitive`: custom provider, stub siteverify `Content-Type: Application/JSON` and `{"success":true}`, solver POST; assert 302 and `crowdsec_captcha_gate`. Do not copy a hunt worktree file as dest.

## 3. Verify

- [ ] 3.1 `go test ./pkg/captcha -count=1` including the new hunt name and `Test_ServeHTTP_dummyProviderSolveIssuesGateCookie`
