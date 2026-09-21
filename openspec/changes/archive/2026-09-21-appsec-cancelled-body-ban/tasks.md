## 1. Regression test (#395)



- [x] 1.1 In `pkg/appsec/zzz_query_test.go`, add a table-driven test (comment cites [maxlerebourg/crowdsec-bouncer-traefik-plugin#395](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/395)) that simulates a readable POST body whose read fails with `context.Canceled` (and optionally `io.ErrUnexpectedEOF`) during `io.ReadAll` in the buffer path.

- [x] 1.2 **Pre-fix assertion:** with `FailureAction: passthrough`, `Query` returns an error wrapping `appsecQuery:GetBody` (not allow); httptest AppSec server receives no request.

- [x] 1.3 **Post-fix assertion:** with `FailureAction: passthrough`, `Query` returns allow (nil error / allow response); AppSec server still not called; with `ban`, `Query` returns a failure-action ban error (not a structured AppSec JSON ban).



## 2. Product fix



- [x] 2.1 Add a small `errors.Is` helper (same file or private func in `query.go`) for client-gone read errors: `context.Canceled`, `context.DeadlineExceeded`, `io.ErrUnexpectedEOF`.

- [x] 2.2 In `newAppsecBodyRequest`, on `io.ReadAll` failure: if client-gone, `return nil, resultForFailureActionErr(pol.FailureAction, "appsecQuery:clientBodyDropped")`; else keep `fmt.Errorf("appsecQuery:GetBody %w", err)`.

- [x] 2.3 Run `go test ./pkg/appsec/...` and any existing failure-action tests; flip the #395 test from red to green.



## 3. OpenSpec and docs



- [x] 3.1 Confirm change delta matches folded `core_plugin_appsec_failure-action` scenarios (client body dropped passthrough/ban).

- [x] 3.2 After implement, devdocsimpact: update `knowledge/devdocs/core_plugin_appsec.md` FailureAction section with client-body-dropped vs unreadable vs GetBody unclassified.

