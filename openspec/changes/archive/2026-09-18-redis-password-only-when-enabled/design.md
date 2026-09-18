## Context

See `proposal.md` Why. `ValidateParams` (`pkg/configuration/configuration.go`) calls `GetVariable(config, "RedisCachePassword")` after the trusted-IP checks with no `RedisCacheEnabled` guard. `GetVariable` Stats and reads `<key>File` when that path is non-empty; a missing, directory, or unreadable path is a validation error. `New()` defaults `RedisCacheEnabled` to false. Disabled Redis opens a local TTL map; the password is unused.

Captcha already gates `GetVariable` behind provider-set (`validateEnabledCaptchaSettings`). This change does not widen that sibling; Redis password is a different gate.

FindSpecHost:

```
verdicts:
  - { deltaId: redis-password-file-gate, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_cache_redis_utilities-client, core_plugin_middleware_bouncer, core_plugin_lapi_reclaim-key] }
```

Search: `core_plugin_middleware_config-validation` owns `ValidateParams` startup rules. This is one added requirement (bugfix) on that leaf. `core_cache_redis_utilities-client` is the Redis client, not the startup gate. `core_plugin_middleware_bouncer` is `New` / Bouncer. `core_plugin_lapi_reclaim-key` is reclaim hashing (Prepare leftover stays out of scope). Small adjustment → fold.

## Goals / Non-Goals

**Goals:**

- Disabled Redis plus a leftover or missing password file starts.
- Enabled Redis still fails on a missing, directory, or unreadable password file.
- Empty password with empty file path stays accepted when Redis is on.

**Non-Goals:**

- Changing `GetVariable`.
- Guarding `lapi.Prepare` (discarded error; leftover readable file can still load into the reclaim hash). Noted in `issues.md`.
- Validating Redis host, database, or read hosts.
- README or a new usage packet.

## Decisions

1. **One `if` at the call site.** Wrap only `GetVariable(config, "RedisCachePassword")` in `if config.RedisCacheEnabled`. Alternative: add an enabled check inside `GetVariable` — rejected; that helper is shared and the ticket forbids changing it. Alternative: skip when the file path is set and Redis is off without reading enabled — rejected; the owner flag is `RedisCacheEnabled`.
2. **Enabled path unchanged.** Do not add a required-password check. Today's empty-string success when no file is set stays.
3. **Test in the existing file.** `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` in `pkg/configuration/zzz_configuration_test.go`. No `TestHunt_` prefix or new file. Pair disabled+missing/stale (accept) with enabled+missing (reject).
4. **Fold, do not add a leaf.** One requirement on `core_plugin_middleware_config-validation`.

## Risks / Trade-offs

- [`lapi.Prepare` still Stats the file after a passing `ValidateParams`] → Accepted. The error is discarded; a leftover readable file can still load into `storeParams`. Follow-up is already noted.
- [A directory-as-file case needs a real path in the test] → Use a temp missing path for both missing cases and a temp directory for the stale/unreadable disabled case.

## Migration Plan

None. Stricter only for enabled Redis plus a bad file (already fails today). Disabled Redis plus a leftover file starts, which is the fix. Rollback is revert.
