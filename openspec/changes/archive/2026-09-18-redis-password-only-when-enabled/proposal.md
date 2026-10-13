## Why

`ValidateParams` always resolves `RedisCachePassword` through `GetVariable`. A config with `redisCacheEnabled: false` and a stale or missing `redisCachePasswordFile` fails startup even though the password is unused (`New()` defaults Redis off).

## What Changes

- Gate the `ValidateParams` `GetVariable(config, "RedisCachePassword")` call on `redisCacheEnabled`.
- When Redis is off, do not Stat or read `redisCachePasswordFile`.
- When Redis is on, keep today's file-error fail and empty-string success.
- Add `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` pairing disabled+missing/stale file (accept) with enabled+missing file (reject).
- Not **BREAKING**. Disabled-Redis leftovers that already start stay accepted; enabled-Redis file errors stay rejected.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: `ValidateParams` resolves `RedisCachePassword` / `RedisCachePasswordFile` only when `redisCacheEnabled` is true.

## Impact

- `pkg/configuration/configuration.go` (`ValidateParams` only)
- `pkg/configuration/zzz_configuration_test.go`
- Out of scope: `GetVariable` itself; `lapi.Prepare`; Redis host/database/read-host validation; README
