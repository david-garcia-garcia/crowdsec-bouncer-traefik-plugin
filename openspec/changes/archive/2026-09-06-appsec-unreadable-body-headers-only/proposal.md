## Why

AppSec-enabled deployments with default `crowdsecAppsecFailureAction: ban` silently 403 long-lived gRPC streams (HTTP/2 POST, `Content-Length` absent) even when LAPI has no decision. Unreadable body is not AppSec-down; lua-cs-bouncer defaults to a headers-only AppSec check (`APPSEC_DROP_UNREADABLE_BODY=false`).

## What Changes

- When `isBodyUnreadable` (HTTP/2 or HTTP/3, body present, `ContentLength < 0`), `appsec.Client.Query` always sends a headers-only GET to AppSec. It MUST NOT return `appsecQuery:unreadableBody dropped` for POST/PUT/PATCH/DELETE.
- `CrowdsecAppsecFailureAction` default stays `ban`. It still covers AppSec HTTP 500 and unreachable (dial / 502 / 503 / 504), including those outcomes on the headers-only GET.
- README documents that unreadable bodies are headers-only, not a failure-action drop.
- **Not BREAKING.** No new public key. No re-add of `crowdsecAppsecUnreadableBodyBlock`. Operators who relied on default `ban` to drop gRPC lose that side effect (the #323 bug).

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: Unreadable HTTP/2+ bodies are headers-only AppSec GET regardless of `crowdsecAppsecFailureAction`. Failure action no longer drops those requests before AppSec.

## Impact

- `pkg/appsec/query.go` (`newAppsecBodyRequest` unreadable-body branch)
- `pkg/appsec/query_test.go` (`Test_appsecQuery_dropUnreadableBody` and streaming coverage)
- `openspec/specs/core_plugin_appsec_failure-action/spec.md` (via this delta)
- README `CrowdsecAppsecFailureAction` text
- `knowledge/devdocs/core_plugin_appsec.md` usage bullet (implement / devdocs impact)
