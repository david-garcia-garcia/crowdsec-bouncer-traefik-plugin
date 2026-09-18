## 1. Encode the CAPI login body

- [x] 1.1 Add an unexported request struct next to `Login` with JSON tags `machine_id`, `password`, `scenarios`
- [x] 1.2 Replace the `getToken` sprintf template with `json.Marshal` of that struct from `c.crowdsecMachineID`, `c.crowdsecPassword`, `c.crowdsecScenarios`
- [x] 1.3 On marshal error return `fmt.Errorf("getToken:marshal %w", err)` and do not POST
- [x] 1.4 Leave `sendQuery(..., false)`, login route, headers, token write, and `code == 200` checks unchanged

## 2. Regression tests

- [x] 2.1 Add `TestGetToken_LoginBodyIsValidJSON` in `pkg/lapi/zzz_client_http_test.go` that captures the login POST, unmarshals it, and compares all three fields to Client values containing `"`, `\`, and a newline
- [x] 2.2 Cover empty `crowdsecScenarios` (`[]`) and nil `crowdsecScenarios` (`null`)
- [x] 2.3 Keep `TestGetToken_UnauthorizedLoginDoesNotRecurse` and the renewal/drain tests green

## 3. Spec purpose

- [x] 3.1 Extend `openspec/specs/core_plugin_lapi_query-round-trip/spec.md` Purpose so the leaf names login-body encoding as well as renewal, drain, and failure messages

## 4. Verify

- [ ] 4.1 `go test ./pkg/lapi -count=1 -run 'TestGetToken_|TestCrowdsecQuery_'`
- [ ] 4.2 `go test ./pkg/... -count=1` and `go vet ./...`
