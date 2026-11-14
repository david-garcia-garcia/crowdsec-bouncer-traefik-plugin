## Why

CrowdSec AppSec answers `{"action":"captcha","http_status":403}` when a rule or hook calls `SetRemediation("captcha")`. `captcha` is one of CrowdSec's four official remediations, and CrowdSec never sends a body with it: the protocol leaves rendering to the bouncer's own captcha. The plugin relays that envelope as-is, so the visitor gets a blank 403 instead of a captcha. Any custom AppSec action without a body ends the same way, as an empty page.

## What Changes

- An AppSec `captcha` verdict goes through this router's captcha gate, like a CrowdSec captcha decision: challenge page, solved gate cookie continues, no usable captcha client downgrades to the ban page. Metrics origin `appsec`, header `captcha:appsec`. The envelope's `http_status` and body are not written.
- When a captcha action rule matched, an AppSec `captcha` defers to that rule's captcha gate, as a non-empty `challenge` already does.
- An AppSec action other than `allow`, `ban`, `captcha`, `challenge` with an empty `user_body_content` bans with new header reason `appsec-action-empty` instead of writing an empty page. With a body it is still relayed.
- When AppSec lets a request through, a POST carrying the challenge marker `crowdsec_captcha_challenge=v1` on a router with a usable captcha client goes to the captcha gate instead of origin, so an AppSec captcha can be solved even when the operator's rule does not match the form POST.
- **BREAKING (contract):** requirement "AppSec captcha envelope is parsed and relayed" (MUST NOT use `pkg/captcha`, empty body relays status) is removed. No Config key changes.

## Capabilities

### New Capabilities

- None.

### Modified Capabilities

- `core_plugin_appsec_bot-detection`: relay is limited to `challenge` and bodied unknown actions; bodyless unknown actions ban; AppSec `captcha` uses the captcha gate; challenge-marker POST let through by AppSec stays on the captcha gate.
- `core_plugin_middleware_bouncer`: header table gains `ban:appsec-action-empty`; `captcha:appsec` now means the router captcha served for an AppSec `captcha` verdict.

## Impact

- `pkg/bouncer/bouncer.go` (`applyAppsecServeHTTP`, `serveAppSec`, `handleCaptchaKindServeHTTP` parameters), `pkg/bouncer/remediation_header.go` (new closed reason).
- Tests in `pkg/bouncer` (replace the two blank-relay captcha tests), mock e2e AppSec stand-in plus a scenario.
- Docs: `README.md` header table and AppSec section, `knowledge/devdocs/core_plugin_appsec.md`, `knowledge/devdocs/core_plugin_middleware_captcha-routing.md`.
- Upstream references: maxlerebourg/crowdsec-bouncer-traefik-plugin issues #357, #402 (point 3), #389, #354; PRs #343, #403 (commit 3), #428.
