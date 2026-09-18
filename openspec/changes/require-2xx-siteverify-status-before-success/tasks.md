## 1. Status gate

- [ ] 1.1 In `Validate`, after `PostForm` succeeds, reject `StatusCode` outside 200–299 before Content-Type; return `(false, nil)`; Debug the status
- [ ] 1.2 Leave `PostForm` `err`, Content-Type miss, decode `err`, and `ServeHTTP` mint/302 unchanged

## 2. Regression

- [ ] 2.1 Add a `pkg/captcha/` `zzz_*_test.go` case (prefer `zzz_servehttp_test.go`): stub siteverify `500` + JSON `{"success":true}`; POST a token; assert `200`, no `crowdsec_captcha_gate`, not `302`
- [ ] 2.2 Keep the existing `200` + JSON `success` solve test green

## 3. Verify

- [ ] 3.1 `go test ./pkg/captcha/ -count=1`
