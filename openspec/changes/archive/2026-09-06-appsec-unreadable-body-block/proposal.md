## Why

This PR already sends a headers-only AppSec GET for HTTP/2+ bodies that cannot be buffered, so default AppSec no longer 403s gRPC streams (#323). Operators who want lua `APPSEC_DROP_UNREADABLE_BODY=true` (drop uninspectable streams) have no dedicated knob; DestBranch only did that as a side effect of default `crowdsecAppsecFailureAction: ban`.

## What Changes

- Restore public config `crowdsecAppsecUnreadableBodyBlock` (`CrowdsecAppsecUnreadableBodyBlock`). Default **false**: headers-only AppSec GET (this PR’s #323 fix). **true**: drop POST/PUT/PATCH/DELETE when `isBodyUnreadable`; GET/HEAD still headers-only.
- The bool is independent of `crowdsecAppsecFailureAction`. `passthrough` does not override a true drop. Failure action still applies to a headers-only GET’s 500/unreachable/`captcha`.
- Retract the live claim that `crowdsecAppsecUnreadableBodyBlock` is removed. `crowdsecAppsecFailureBlock` and `crowdsecAppsecUnreachableBlock` stay removed.
- **Not BREAKING.** Omit/false matches this PR’s current headers-only behavior. Operators who want DestBranch’s implicit gRPC drop set the bool true.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_failure-action`: Unreadable HTTP/2+ bodies are headers-only AppSec GET unless `crowdsecAppsecUnreadableBodyBlock` is true. Failure action no longer owns that drop. The unreadable-body bool is restored; the other two block bools stay gone.

## Impact

- `pkg/configuration/configuration.go` (`Config` + `New()` default false)
- `pkg/appsec/query.go` (`Policy`, `newAppsecBodyRequest`, restore `isMethodWithBody`)
- `pkg/bouncer/bouncer.go` (per-router Policy field)
- `pkg/appsec/query_test.go`
- `openspec/specs/core_plugin_appsec_failure-action/spec.md` (via this delta)
- README `CrowdsecAppsecFailureAction` + new key
- `knowledge/devdocs/core_plugin_appsec.md` usage
