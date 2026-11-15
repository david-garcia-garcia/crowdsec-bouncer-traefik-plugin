## Why

CrowdSec's challenge protocol treats AppSec HTTP 401 and any unexpected listener status as the configured AppSec failure behaviour. This fork already applies `bouncerAppsecFailureAction` to HTTP 500 and to unreachable 502/503/504, but a bare 401 still becomes `appsecQuery statusCode:401` and the bouncer bans it. Community PR https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 (issue 402 point 2) closed that gap on the bool-based plugin; this fork still has it on the enum. We are not copying their patch.

## What Changes

- `appsec.Client.Query` applies `bouncerAppsecFailureAction` to HTTP 401 and other unexpected listener statuses (not 200, not 403 fail-closed, not 500, not 502/503/504) when the body has no parseable non-empty JSON `action`.
- `passthrough` on those statuses allows (Query returns allow; bouncer calls next). `ban` forbids. `captcha` returns `ErrFailureCaptcha`.
- Log that failure at Error with slog attr `statusCode` on stem `appsecQuery:failure`.
- HTTP 403 with empty or invalid JSON stays fail-closed ban. Parseable JSON with a non-empty action remains a verdict.
- HTTP 500, 502/503/504, client disconnect, and body limits are unchanged.
- Spec `core_plugin_appsec_failure-action` drops the legacy-ban sentence and adds 401/unexpected scenarios.
- Spec `core_plugin_appsec_bot-detection` names 401/unexpected next to 500/unreachable on FailureAction.

## Capabilities

### New Capabilities

### Modified Capabilities

- `core_plugin_appsec_failure-action`: 401 and unexpected AppSec statuses follow `bouncerAppsecFailureAction` the same way 500 does; 403 empty/invalid JSON stays ban; 502/503/504 stay unreachable.
- `core_plugin_appsec_bot-detection`: Query's FailureAction coverage includes 401 and unexpected statuses, not only 500 and unreachable.

## Impact

- `pkg/appsec/query.go` (`Query` after `interpretAppsecBody`)
- `pkg/appsec/zzz_failure_action_test.go` (401/unexpected regression)
- `openspec/specs/core_plugin_appsec_failure-action/spec.md`
- `openspec/specs/core_plugin_appsec_bot-detection/spec.md`
- Usage `knowledge/devdocs/core_plugin_appsec.md` (devdocs impact)
- Operators with `bouncerAppsecFailureAction: passthrough` will allow requests when AppSec answers 401 (auth/key cache miss) instead of banning every visitor
