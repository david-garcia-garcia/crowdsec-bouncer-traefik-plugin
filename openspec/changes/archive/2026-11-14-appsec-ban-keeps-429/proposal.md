## Why

CrowdSec AppSec `RateLimit()` (CrowdSec v1.8.2+) blocks a client with `{"action":"ban","http_status":429}` on a listener 403. The bouncer answers every AppSec ban with `bouncerRemediationStatusCode` (403 by default), so clients that back off on 429 keep retrying. Upstream fixed the same job in https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/422 (issue https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/421); this fork cannot copy that patch because master has no root `bouncer.go`.

## What Changes

- An AppSec ban whose `http_status` is 429 is answered with 429, with the same operator ban template, `Content-Type`, `Cache-Control`, remediation header (`ban:appsec`), and dropped metrics.
- Any other AppSec ban `http_status` keeps `bouncerRemediationStatusCode`. 429 wins over a configured `bouncerRemediationStatusCode`.
- No `Retry-After`. LAPI bans, action rules, failure actions, and captcha downgrade keep `bouncerRemediationStatusCode`.
- Real e2e: CrowdSec image `v1.8.0` → `v1.8.2`, a local appsec-config using `RateLimit()`, and a Pester case that sees 429 with the ban page.
- README documents the 429 exception.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- core_plugin_appsec_bot-detection: "Structured ban keeps the operator ban template" answers an AppSec ban with `http_status` 429 with 429 instead of `bouncerRemediationStatusCode`.

## Impact

- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`, `handleBanServeHTTP`)
- `pkg/bouncer` unit tests
- `tests/e2e/real/config/docker-compose.test.yml`, `tests/e2e/real/config/acquis.yaml`, `tests/e2e/real/config/appsec-configs/`, `tests/e2e/real/appsec.Tests.ps1`
- `README.md`
- Usage packets `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`, `knowledge/devdocs/build_e2e_real.md`
