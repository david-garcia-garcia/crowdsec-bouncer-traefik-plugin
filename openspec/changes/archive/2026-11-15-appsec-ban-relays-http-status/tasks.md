## 1. Regression tests

- [x] 1.1 `TestHandleNextServeHTTPAppsecBanStatus`: ban/418 → 418; ban/403 with `remediationStatusCode` 503 → 403; ban/200 → 200; ban/599 → 599 (fail on master)
- [x] 1.2 Same table: ban/204 → 204 with an empty body (fails on master)
- [x] 1.3 Same table: ban/99, ban/199, ban/600, and ban without `http_status` → `remediationStatusCode`

## 2. Bouncer

- [x] 2.1 `appsecBanStatusCode` returns `http_status` when from 200 to 599, else `remediationStatusCode`
- [x] 2.2 `handleBanStatusServeHTTP` skips the template body for 204 and 304

## 3. Mock e2e

- [x] 3.1 AppSec mock answers `appsec-418` with `{"action":"ban","http_status":418}`
- [x] 3.2 `appsec` scenario expects 418 on `/foo/appsec-418`

## 4. Docs

- [x] 4.1 README remediation table and `BouncerRemediationStatusCode` entry document the relay and `user_blocked_http_code`
- [x] 4.2 Update `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`, `knowledge/devdocs/index_core_plugin.md`, and `knowledge/devdocs/build_e2e_mock.md`

## 5. Verify

- [x] 5.1 Run `go vet` and `go test ./pkg/... .` on this machine
- [x] 5.2 Run the mock e2e `appsec` scenario (Linux container, Traefik v3.7.11)
