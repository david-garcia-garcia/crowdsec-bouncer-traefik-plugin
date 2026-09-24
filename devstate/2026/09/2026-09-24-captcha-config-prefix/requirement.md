# Requirement
IssueKey: 2026-09-24-captcha-config-prefix

## Problem
Owner-read captcha knobs still live on the `BouncerCaptcha` / `bouncerCaptcha*` public stem even though `pkg/captcha` is the piece that reads them. The live config-validation spec froze that spelling. The ticket replaces that freeze: Go field names and JSON tags both move to the `Captcha` / `captcha*` stem. Breaking the public contract is accepted (product still beta). No old-key aliases.

## Current (code)
- The seventeen listed fields are `BouncerCaptcha*` with `json:"bouncerCaptcha*"` on `Config`: `pkg/configuration/configuration.go`.
- `CreateConfig` / `configuration.New` defaults those same `BouncerCaptcha*` names: `pkg/configuration/configuration.go`.
- No alias tags or old-key decode: `pkg/configuration/configuration.go` (one JSON tag per field).
- `pkg/captcha` reads them as instance-owned Open-key knobs: `pkg/captcha/session.go` `ownershipFrom` and `newOwnerClient` (`GetVariable` strings `"BouncerCaptchaSiteKey"`, `"BouncerCaptchaSecretKey"`, `"BouncerCaptchaGateSecret"` plus the other `cfg.BouncerCaptcha*` fields).
- Validation names the old Go fields: `pkg/configuration/configuration.go` `validateEnabledCaptchaSettings`, `validateCaptchaCredentials`, `validateCaptcha` (errors such as `BouncerCaptchaSiteKey: cannot be empty when BouncerCaptchaProvider is set`, `BouncerCaptchaCustomValidateBody: must be empty, form, or json`).
- Live spec freezes owner-read captcha settings as `bouncerCaptcha*` and `GetVariable` example `BouncerCaptchaSiteKey`: `openspec/specs/core_plugin_middleware_config-validation/spec.md`.
- `CaptchaEnabled` / `captchaEnabled` and `CaptchaInstanceName` / `captchaInstanceName` already exist: `pkg/configuration/configuration.go`.
- Bounce-decision fields stay on the bouncer stem: `BouncerLapiFailureAction`, `BouncerAppsecFailureAction`, `BouncerBanFilePath`, `BouncerRemediationHeadersCustomName`, `BouncerRemediationStatusCode` — `pkg/configuration/configuration.go`.
- README documents `BouncerCaptcha*` / `bouncerCaptcha*`: `README.md`.
- Real e2e compose labels use `bouncerCaptcha*`: `tests/e2e/real/config/docker-compose.test.yml`.
- Tests assign and assert the old names: `pkg/configuration/zzz_configuration_test.go`, `zzz_plugin_test.go`, `zzz_constructor_test.go`.

## Desired
- Rename the seventeen listed fields: Go `BouncerCaptcha*` → `Captcha*`, JSON `bouncerCaptcha*` → `captcha*`.
- Do not keep old-key aliases.
- Leave `CaptchaEnabled` / `CaptchaInstanceName` as they are.
- Leave `BouncerLapiFailureAction`, `BouncerAppsecFailureAction`, `BouncerBanFilePath`, `BouncerRemediationHeadersCustomName`, `BouncerRemediationStatusCode` on the bouncer stem (value may be the word `captcha`).
- Replace the recorded spec freeze that owner-read captcha settings stay `bouncerCaptcha*`.
- Move `GetVariable` lookup strings, validation error text, README, e2e labels, and tests that name the old keys with the fields.

## Affected
- `pkg/configuration/configuration.go` — public fields, defaults, `GetVariable` keys, validation errors
- `pkg/captcha/session.go` — owner Open-key reads
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` — recorded `bouncerCaptcha*` freeze
- `README.md`
- `tests/e2e/real/config/docker-compose.test.yml`
- Tests that name the old keys (`pkg/configuration/zzz_configuration_test.go`, `zzz_plugin_test.go`, `zzz_constructor_test.go`)

## Out of scope
- Renaming bounce-decision fields (`BouncerLapiFailureAction`, `BouncerAppsecFailureAction`, `BouncerBanFilePath`, `BouncerRemediationHeadersCustomName`, `BouncerRemediationStatusCode`).
- Changing `CaptchaEnabled` / `CaptchaInstanceName`.
- Keeping `bouncerCaptcha*` aliases for old operator YAML.
- Rewriting archived OpenSpec change folders.

## Unknowns
- Full file list that still spells `bouncerCaptcha*` (mock e2e YAML, examples, sibling live specs, usage docs). Explore owns the inventory.
- Whether leftover `bouncerCaptcha*` after the rename should stay non-E2 (today leftover `bouncerCaptcha*` is not an E2 secret; leftover `captchaInstanceName` is).
- Operator blast radius outside this tree.

## Tensions
- Live spec `openspec/specs/core_plugin_middleware_config-validation/spec.md` says owner-read captcha settings SHALL stay `bouncerCaptcha*`. The ticket names that freeze as the thing this rename replaces. Not a requester disagreement; explore must treat the live SHALL as stale.
