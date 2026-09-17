## Why

CrowdSec 1.8 AppSec bot-detection returns a structured challenge (HTML, cookie, `/crowdsec-internal/challenge` callback) instead of an empty WAF 403. This plugin treats any non-200 AppSec status as a ban and drops the body, so enabling `crowdsecurity/appsec-bot-*` silently 403s every client ([issue 389](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/389)). Upstream [PR 343](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/343) defines the JSON protocol; this fork needs that relay on the connection/bouncer split, plus real e2e.

## What Changes

- Parse AppSec JSON (`action`, `http_status`, `user_body_content`, `user_cookies`, `user_headers`) on `CrowdsecConnection.AppsecQuery`.
- `allow` / empty action → pass. `ban` → existing ban template. Any other non-allow action (including `challenge`) → write AppSec status, headers, cookies, and body to the client.
- Legacy empty/non-JSON non-200 stays a ban.
- No new plugin config key. Clamp `http_status` to 100–999. Bound the AppSec response body.
- Unit tests, mock AppSec JSON, and real-stack Pester against CrowdSec 1.8 with bot-detection plus a `/crowdsec-internal/challenge` route through the same middleware.

## Capabilities

### New Capabilities

- `core_plugin_appsec_bot-detection`: Relay CrowdSec AppSec structured remediations (challenge) using `GetRemoteIP` and the existing AppSec client, without a new plugin option.

### Modified Capabilities

- `build_e2e_pester_crowdsec-stack`: Real-stack Pester MUST cover AppSec bot-detection against CrowdSec 1.8, and the pinned CrowdSec image MUST be `v1.8.0`.

## Impact

- `pkg/crowdsecconnection` (`AppsecQuery` return value, parse, body cap) and `pkg/bouncer` (relay writer vs ban template).
- `pkg/crowdsecconnection/appsec_test.go` and bouncer tests.
- `tests/e2e/mock/mocklapi` AppSec JSON + existing `appsec` scenario (or sibling).
- `tests/e2e/real/` compose image, acquis, challenge router, Pester.
- README / examples only if operators must wire the challenge path (no new middleware key).
