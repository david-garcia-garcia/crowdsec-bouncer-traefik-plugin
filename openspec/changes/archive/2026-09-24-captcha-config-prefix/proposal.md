## Why

Owner-read captcha knobs still live on the `BouncerCaptcha` / `bouncerCaptcha*` public stem even though `pkg/captcha` is the piece that reads them. The live config-validation spec froze that spelling; this change replaces that freeze so the captcha stem matches the owner.

## What Changes

- Rename the seventeen owner-read captcha fields: Go `BouncerCaptcha*` → `Captcha*`, JSON `bouncerCaptcha*` → `captcha*`. Reorder `Config` so the new block sits with `CaptchaEnabled` / `CaptchaInstanceName` (alphabetical by json tag).
- **BREAKING**: no old-key aliases. Traefik mapstructure-matches the field name; leftover `bouncerCaptcha*` never reaches `New`. Operators must rename labels/YAML. A leftover pre-prefix `captchaFilePath` starts matching `CaptchaFilePath` again (the captcha stem, not an alias).
- Leave `CaptchaEnabled` / `CaptchaInstanceName` as they are.
- Leave bounce-decision fields on the bouncer stem (`BouncerLapiFailureAction`, `BouncerAppsecFailureAction`, `BouncerBanFilePath`, `BouncerRemediationHeadersCustomName`, `BouncerRemediationStatusCode`) even when a value is the word `captcha`.
- Move `GetVariable` lookup strings, validation error text, README, examples, e2e labels, and tests with the fields.
- Leftover owner-read captcha knobs stay non-E2 (`validateOpenVsSubscribe` still passes `secretPresent=false` for captcha). Leftover `captchaInstanceName` stays E2.
- Fold the five live catalog leaves that still name the old stem as current contract. No new spec family.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_config-validation`: owner-read captcha settings are `captcha*` / `Captcha*`; `GetVariable` and validation errors use the new Go names; leftover `bouncerCaptcha*` is dropped like any unused key; leftover owner-read `captcha*` stays non-E2.
- `core_plugin_middleware_captcha-gate`: gate secret and leftover-provider scenarios use `CaptchaGateSecret` / leftover `captchaProvider`.
- `core_plugin_middleware_bouncer`: siteverify timeout and owner pass-through use `CaptchaSiteverifyHTTPTimeoutSeconds` / `CaptchaSiteKey`; bounce-only leftover keys are `captcha*`.
- `core_plugin_lapi_reclaim-key`: the captcha timeout knob excluded from SessionHex and the LAPI ownership key is `CaptchaSiteverifyHTTPTimeoutSeconds`.
- `build_e2e_pester_crowdsec-stack`: compose labels and captcha-grace cases use `captcha*` owner-read keys; owning captcha still requires `captchaEnabled`, not a set `captchaProvider` alone.

## Impact

- `pkg/configuration/configuration.go` — public fields, JSON tags, defaults, `GetVariable` keys, `ValidateParams` error text.
- `pkg/captcha/session.go` — owner Open-key reads (`GetVariable` strings and `cfg.Captcha*` knobs). `pkg/captcha` locals stay `siteKey` / `secretKey` / `gateSecret`.
- README (BREAKING names the stem move), `examples/captcha/`, `examples/custom-captcha/`, real compose labels, mock e2e YAML, unit tests that name the old keys (explore inventory: 34 current-contract files).
- Live catalog deltas in this change folder. Usage packets move with implement / `opd-devdocsimpact`.
- **BREAKING** for every operator file that still uses `bouncerCaptcha*`.
