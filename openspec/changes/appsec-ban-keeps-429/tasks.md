## 1. Regression tests

- [x] 1.1 Add a `pkg/bouncer` table test that fails on master: AppSec ban/429 → 429 with the operator ban template and `ban:appsec`
- [x] 1.2 Same table: ban/403, ban/418, and ban without `http_status` → `remediationStatusCode`
- [x] 1.3 Same table: ban/429 with `remediationStatusCode` 503 → 429; HEAD + ban/429 → 429 with empty body

## 2. Bouncer

- [x] 2.1 Split `handleBanServeHTTP` into the existing entry point and a ban writer that takes the status; existing callers unchanged
- [x] 2.2 Add a `Bouncer` helper that returns 429 for an AppSec ban with `http_status` 429, else `remediationStatusCode`, and use it in `applyAppsecServeHTTP` `case appsec.ActionBan`

## 3. Real e2e

- [x] 3.1 Bump `crowdsecurity/crowdsec` to `v1.8.2` in `tests/e2e/real/config/docker-compose.test.yml`
- [x] 3.2 Add `tests/e2e/real/config/appsec-configs/e2e-rate-limit.yaml` (`RateLimit()` on `/ratelimit`), mount it, and list it in `acquis.yaml` next to `crowdsecurity/crs-inband`
- [x] 3.3 Add an AppSec-only router and middleware `/ratelimit` on the 7422 listener with the e2e ban page and remediation header
- [x] 3.4 Add a Pester case in `tests/e2e/real/appsec.Tests.ps1`: requests under the limit pass, the next one is 429 with the ban page and `ban:appsec`

## 4. Docs

- [x] 4.1 README remediation table and `BouncerRemediationStatusCode` entry document the AppSec 429 exception
- [x] 4.2 Update `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`, and `knowledge/devdocs/build_e2e_real.md`

## 5. Verify

- [x] 5.1 Run `go test ./pkg/...` on this machine
- [x] 5.2 Run the real-stack e2e `appsec.Tests.ps1` on this machine
