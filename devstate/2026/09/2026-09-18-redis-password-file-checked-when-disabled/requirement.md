# Requirement
IssueKey: 2026-09-18-redis-password-file-checked-when-disabled

## Problem
`ValidateParams` always resolves `RedisCachePassword` through `GetVariable`, so `redisCacheEnabled: false` plus a stale or missing `redisCachePasswordFile` fails startup.

## Current (code)
- `ValidateParams` calls `GetVariable(config, "RedisCachePassword")` with no `RedisCacheEnabled` guard after the trusted-IP checks. `pkg/configuration/configuration.go`
- `GetVariable` Stats and reads `<key>File` when that path is non-empty; a missing, directory, or unreadable path is a validation error. Empty file path uses the string field. `pkg/configuration/configuration.go`
- `New()` defaults `RedisCacheEnabled` to false. `pkg/configuration/configuration.go`
- `Test_ValidateParams` has no `redisCacheEnabled: false` plus missing/stale password-file case. Cited hunt test `TestHunt_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` is not in this tree. `pkg/configuration/zzz_configuration_test.go`
- Config-validation spec has no Redis password-file gate. `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- `lapi.Prepare` also calls `GetVariable` for `RedisCachePassword` with no enabled guard (error discarded). `pkg/lapi/client.go`

## Desired
- Resolve or require `RedisCachePassword` / `RedisCachePasswordFile` only when `redisCacheEnabled` is true.
- Include a regression test for disabled Redis plus a stale or missing password file.
- Bound to this defect only.

## Affected
- `pkg/configuration/configuration.go` (`ValidateParams`)
- `pkg/configuration/zzz_configuration_test.go`

## Out of scope
- Gating `lapi.Prepare` Redis password resolve
- Validating Redis host, database, or read hosts
- Changing `GetVariable` itself
- Other `ValidateParams` gaps
- Spec or README work not asked by the ticket

## Unknowns
- Whether an empty password is still accepted when Redis is enabled (today `GetVariable` allows empty when no file is set).
- Where the cited hunt test should live; dest has no `TestHunt_*` file.

## Tensions
- Ticket cites `TestHunt_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` as proven FAIL; that test is not on dest.
- Ticket lines 326-328 match dest `ValidateParams`.
- `lapi.Prepare` still resolves the same file later; ticket bounds the ask to `ValidateParams` only.
