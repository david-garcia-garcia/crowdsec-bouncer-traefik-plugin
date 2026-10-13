# Explore

## Concepts

```
plugin.New
  │
  ├─ ValidateParams
  │    GetVariable(RedisCachePassword)   ← always, no RedisCacheEnabled guard
  │
  ├─ lapi.Prepare
  │    GetVariable(RedisCachePassword)   ← error discarded (out of scope)
  │
  └─ OpenDecisionStore → cache.New(isRedis=RedisCacheEnabled)
       true  → SimpleRedis(pass)
       false → local TTL map (pass unused)
```

`ValidateParams` is the startup gate (`plugin.go` before `lapi.Prepare`). `GetVariable` Stats and reads `<key>File` when that path is non-empty; a missing, directory, or unreadable path is an error. Empty file path uses the string field, including empty. `New()` defaults `RedisCacheEnabled` to false.

Captcha already gates `GetVariable` behind provider-set (`validateEnabledCaptchaSettings`). Redis password does not. Config-validation spec has no Redis password-file gate. Cited hunt test `TestHunt_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` is not on dest.

`Test_GetVariable` / invalid file path: pass (`pkg/configuration`, 2026-09-18T14:18:21Z). Hunt path: not reproduced (test absent). Defect grounded from the ungated call at `ValidateParams` plus `GetVariable` file-error behavior.

Consumed: `knowledge/devdocs/index.md`, `index_core_cache.md` / `core_cache_redis.md`, `index_core_plugin.md` / `core_plugin_middleware.md`, `index_std_go.md` / `std_go_test_zzz-prefix.md`, `knowledge/research/index.md` / `index_ext_redis.md`. No usage or Language write (cache packet is the Redis client, not ValidateParams). No research write (this is our gate, not Redis AUTH). No identity reconstruct. No reclaim / process-lifetime change.

## Decisions

1. **Gate** — wrap only the `ValidateParams` `GetVariable(config, "RedisCachePassword")` call in `if config.RedisCacheEnabled`. Do not change `GetVariable`. Do not validate Redis host, database, or read hosts.
2. **Enabled path unchanged** — when Redis is on, missing/stale/unreadable `redisCachePasswordFile` still fails startup. Empty password with empty file path stays accepted.
3. **Prepare** — leave `lapi.Prepare` unguarded. Noted as follow-up.
4. **Test** — add `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled` in `pkg/configuration/zzz_configuration_test.go`. No `TestHunt_` prefix. Pair disabled+missing/stale file (accept) with enabled+missing file (reject).
5. **Spec / docs** — propose folds one requirement onto existing `core_plugin_middleware_config-validation`. No README. No new usage packet.
6. **Smallest delta** — one `if` plus the regression test. No neighborhood cleanup.

## Open questions

- Q: Is an empty Redis password still accepted when Redis is enabled and no password file is set?
  Decision: assumed — yes; keep today’s `GetVariable` empty-string success. Do not add a required-password check.
  By: explore

- Q: Where should the cited hunt test live, given dest has no `TestHunt_*` file?
  Decision: resolved — `pkg/configuration/zzz_configuration_test.go` as `Test_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled`. Do not invent a `TestHunt_` file.
  By: explore

- Q: Should this change also guard `lapi.Prepare`’s `GetVariable` for `RedisCachePassword`?
  Decision: assumed — no. Requirement out of scope. Discarded error means a missing file does not fail Prepare; a leftover valid file can still load into the reclaim hash. Noted in `issues.md`.
  By: explore

- Q: Does propose add a spec leaf or a README line for this gate?
  Decision: resolved — fold one requirement onto existing `core_plugin_middleware_config-validation`. Do not edit README.
  By: propose
