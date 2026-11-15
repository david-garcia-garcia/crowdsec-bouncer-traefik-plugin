## Why

The bouncer honours only `http_status` 429 on an AppSec ban (`2026-11-14-appsec-ban-keeps-429`). A CrowdSec rule that sets its own code with `SetReturnCode()`, or an appsec-config with `user_blocked_http_code`, is answered with `bouncerRemediationStatusCode` instead. Upstream relays any `http_status` from 200 to 599 since https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/436 (release v1.8.2). The owner chose to follow upstream (review `upstream-review-2026-11-14.md`, problem 17, option A).

## What Changes

- An AppSec ban is answered with its `http_status` when it is from 200 to 599, with the same operator ban template, `Content-Type`, `Cache-Control`, remediation header (`ban:appsec`), and dropped metrics.
- A zero, missing, or out-of-range `http_status` keeps `bouncerRemediationStatusCode`.
- **BREAKING (behavior):** CrowdSec always sends `http_status` on a ban (403 by default), so `bouncerRemediationStatusCode` no longer sets the status of AppSec bans. An operator with a non-403 `bouncerRemediationStatusCode` now sees 403 on AppSec bans unless `user_blocked_http_code` is set in CrowdSec.
- The ban writer skips the template body for 204 and 304, which net/http does not let carry a body.
- Mock e2e: the AppSec mock answers `appsec-418` with `{"action":"ban","http_status":418}` and the `appsec` scenario expects 418.
- README documents the relay.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- core_plugin_appsec_bot-detection: "Structured ban keeps the operator ban template" answers an AppSec ban with its `http_status` from 200 to 599 instead of only 429.

## Impact

- `pkg/bouncer/bouncer.go` (`appsecBanStatusCode`, `handleBanStatusServeHTTP`)
- `pkg/bouncer` unit tests
- `tests/e2e/mock/mocklapi/main.go`, `tests/e2e/mock/scenarios/appsec/run.sh`
- `README.md`
- Usage packets `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_ban-page.md`, `knowledge/devdocs/index_core_plugin.md`, `knowledge/devdocs/build_e2e_mock.md`
