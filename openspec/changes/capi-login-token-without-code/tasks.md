## 1. Accept token after HTTP 2xx

- [ ] 1.1 In `getToken`, store `login.Token` on the stored transport when it is non-empty. Drop the `login.Code == 200` conjunct. Keep writing on the stored transport, not a Client field
- [ ] 1.2 Keep the existing `getToken statusCode:` plus `login.Code` error when the token is empty. Do not rewrite that string

## 2. Regression

- [ ] 2.1 Add `TestGetToken_TwoXXBodyWithoutJSONCode` in `pkg/lapi/zzz_client_http_test.go`: 2xx body `{"token":"fresh","expire":"later"}` stores `fresh`. Not `TestHunt_*`
- [ ] 2.2 Prove a 2xx empty-token body still returns `getToken statusCode:` (same file). Leave existing `"code":200` stubs unchanged

## 3. Verify

- [ ] 3.1 `go test ./pkg/lapi/ -run TestGetToken_ -count=1`
- [ ] 3.2 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`, `go test . -count=1`, `golangci-lint run ./...`
