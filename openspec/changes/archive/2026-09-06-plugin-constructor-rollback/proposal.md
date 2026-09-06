## Why

`plugin.go` `New` binds LAPI and AppSec reclaim holders but returns errors from later steps without releasing earlier opens. Tickers can keep running after a failed constructor. `crowdsecMode: appsec` with AppSec disabled succeeds and forwards all traffic with no enforcement. Constructor mode branches and error rollback lack tests.

## What Changes

- Wrap backend `Open` calls in a child `context.WithCancel` of Traefik's constructor ctx; cancel on any `New` error so reclaim drops holders immediately.
- Reject `crowdsecMode: appsec` when `crowdsecAppsecEnabled` is false in `plugin.go` after `ValidateParams`.
- Add `plugin_test.go` coverage for appsec-only, live+AppSec keys, stream session, appsec-mode rejection, and LAPI rollback after AppSec failure.

## Capabilities

### Modified Capabilities

- `core_plugin_middleware_instance-reclaim`: constructor rollback on partial failure; appsec mode requires AppSec enabled; plugin tests for mode branches.

## Impact

- `plugin.go`, `plugin_test.go` only.
