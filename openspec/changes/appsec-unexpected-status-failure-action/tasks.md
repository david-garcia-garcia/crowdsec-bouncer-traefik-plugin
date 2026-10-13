## 1. Query FailureAction on unexpected status

- [ ] 1.1 After `interpretAppsecBody`, when the status is not 200 and not 403 and there is no parseable non-empty JSON action, call `resultForFailureAction` with `appsecQuery statusCode:<n>`
- [ ] 1.2 Log that path at Error with slog attr `statusCode` on stem `appsecQuery:failure`
- [ ] 1.3 Leave HTTP 403 empty/invalid JSON, HTTP 500, 502/503/504, disconnect, and body limits unchanged

## 2. Regression tests

- [ ] 2.1 Add a test that fails on dest when 401 ignores passthrough (allow / ban / `ErrFailureCaptcha`)
- [ ] 2.2 Cover one other unexpected status (418) the same way
- [ ] 2.3 Keep `Test_appsecQuery_emptyForbiddenErrors` green (empty 403 still errors under passthrough)
- [ ] 2.4 Run `go test ./pkg/appsec ./pkg/bouncer` on this machine

## 3. Specs

- [ ] 3.1 Confirm delta specs match the Query behavior before archive
