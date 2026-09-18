## Why

`plugin.New` copies a non-empty deprecated `captchaHtmlFilePath` onto `captchaFilePath` even when the current key is already set, so a leftover deprecated path silently replaces the template the operator named. Ban already fills only when the current path is empty; captcha does not.

## What Changes

- Alias `CaptchaHTMLFilePath` onto `CaptchaFilePath` only when `CaptchaFilePath` is empty (same empty-guard as ban).
- When both keys are set, keep `CaptchaFilePath`. Compile and serve follow that field.
- Add `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` in `zzz_plugin_test.go`.
- Retarget mock and real e2e deprecated-only keys to `captchaFilePath` so those suites still compile the scenario/dummy template.
- **Not BREAKING.** Deprecated-only Traefik YAML that never clears `captchaFilePath` already arrives with the `/captcha.html` default; after the guard it keeps that default instead of the deprecated path. Ticket bound that.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: `New` copies the deprecated captcha HTML path only when the current path is empty.

## Impact

- `plugin.go` (captcha alias `if`)
- `zzz_plugin_test.go`
- `tests/e2e/mock/scenarios/captcha/dynamic.yml`
- `tests/e2e/real/docker-compose.test.yml`
- Out of scope: removing `captchaHtmlFilePath`, changing the `/captcha.html` default, ban alias, README, examples, usage-doc rewrites, other hunt findings
