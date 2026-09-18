## Why

Deprecated `banHtmlFilePath` / `captchaHtmlFilePath` still sit on Config and `plugin.New` still copies them. Ban fills `banFilePath` only when that field is empty; captcha overwrites `captchaFilePath` whenever the old key is set. Closed PR #85 tried a quieter empty-guard; the owner declined that alias. The old keys must be deleted.

## What Changes

- Delete `BanHTMLFilePath` and `CaptchaHTMLFilePath` from Config (fields, json tags, comments).
- Delete both `plugin.New` alias copies. `New` snapshots Traefik’s decode and MUST NOT read leftover old keys.
- **BREAKING** for operators who still set only the old keys: Traefik v3.7.11 drops unused keys; those operators get CreateConfig defaults (`banFilePath` empty, `captchaFilePath` `/captcha.html`).
- Retarget live leftovers (`banHtmlFilePath` / `captchaHtmlFilePath` and HTML-cased twins) to `banFilePath` / `captchaFilePath`: real e2e labels, mock captcha YAML, README sample, captcha examples, and the live custom-ban WHEN.
- Leave archived OpenSpec history as-is. Do not add an empty-guard alias test. Do not reuse PR #85.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `build_e2e_pester_crowdsec-stack`: custom-ban WHEN names `banFilePath` instead of `banHtmlFilePath`.

## Impact

- `pkg/configuration/configuration.go` (field delete)
- `plugin.go` (alias-block delete)
- `tests/e2e/real/docker-compose.test.yml`
- `tests/e2e/mock/scenarios/captcha/dynamic.yml`
- `README.md` sample
- `examples/captcha/` and `examples/custom-captcha/`
- `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md` (via this change delta)
