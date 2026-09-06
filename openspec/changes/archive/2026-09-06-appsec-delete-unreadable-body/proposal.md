## Why

Bodyless `DELETE` over HTTP/3 is treated as an unreadable AppSec body because `DELETE` is still in `isMethodWithBody` while quic-go wraps the stream with `ContentLength = -1`. Under default `crowdsecAppsecFailureAction: ban` the bouncer returns 403 before origin. GET/HEAD already skip that drop; DELETE must match them so REST and browser `fetch({ method: "DELETE" })` work on HTTP/3.

## What Changes

- Remove `DELETE` from the AppSec unreadable-body method set (`isMethodWithBody`). POST, PUT, and PATCH stay; gRPC streams remain POST.
- HTTP/3 DELETE with an unreadable body is forwarded to AppSec as a headers-only GET (same as GET/HEAD after #351), not dropped.
- Add a unit test mirroring `Test_appsecQuery_unreadableBodyGetNotDropped` for DELETE.
- **Not BREAKING.** No public Traefik config keys. `crowdsecAppsecFailureAction` defaults and values stay as they are.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: Unreadable-body drop applies to POST, PUT, and PATCH only. DELETE with an unreadable HTTP/2 or HTTP/3 body is not dropped; AppSec is queried headers-only.

## Impact

- `pkg/appsec/query.go` (`isMethodWithBody`)
- `pkg/appsec/query_test.go` (DELETE unreadable-body regression)
- Indirect: `pkg/bouncer/bouncer.go` no longer bans this case under default AppSec failure action
