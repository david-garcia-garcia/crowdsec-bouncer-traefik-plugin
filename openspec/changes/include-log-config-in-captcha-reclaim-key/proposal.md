## Why

A captcha owner rebuilt after only `logLevel` changes from `trace` to `debug` keeps the old TRACE logger. `OwnershipKey` omits `LogLevel`, `LogFilePath`, and `LogFormat`, so reclaim Wakes the same Client and `bindIdentity` does not replace `Client.log`.

## What Changes

- Add `LogLevel`, `LogFilePath`, and `LogFormat` to the captcha `ownership` payload so `OwnershipKey` forks when any of those knobs change.
- A log-config-only rebuild Opens a new captcha Client; `newOwnerClient` stores the rebuilt logger. Existing reclaim orphan / grace / Close and `SetAlias` remap stay as today.
- Do not rebind `Client.log` on reclaim. Do not change LAPI or AppSec reclaim keys. Do not change `pkg/logger` or `plugin.go` `New` logger construction.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-slots`: captcha ownership Open key SHALL include `logLevel`, `logFilePath`, and `logFormat`.

## Impact

- `pkg/captcha/session.go` (`ownership`, `ownershipFrom`)
- `pkg/captcha/zzz_owner_test.go` (key-fork coverage)
- Live SHALL on `openspec/specs/core_plugin_middleware_instance-slots/spec.md`
- Usage packets catch up in devdocs impact (`core_plugin_middleware.md`, `core_plugin_middleware_instance-slots.md`)
- Do not edit `pkg/lapi/identity.go`, `pkg/appsec/session.go`, `pkg/logger`, or `plugin.go` logger construction
