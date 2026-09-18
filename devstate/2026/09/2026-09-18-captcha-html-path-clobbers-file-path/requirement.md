# Requirement
IssueKey: 2026-09-18-captcha-html-path-clobbers-file-path

## Problem
`plugin.New` copies a non-empty deprecated `captchaHtmlFilePath` onto `captchaFilePath` even when the current key is already set, so a leftover deprecated path silently replaces the template the operator named.

## Current (code)
- Ban alias fills only when `BanFilePath` is empty and `BanHTMLFilePath` is not. `plugin.go`
- Captcha alias runs whenever `CaptchaHTMLFilePath` is non-empty and overwrites `CaptchaFilePath`. `plugin.go`
- `CaptchaHTMLFilePath` is deprecated; `CaptchaFilePath` is the current key. `pkg/configuration/configuration.go`
- `CaptchaFilePath` defaults to `/captcha.html`; `BanFilePath` defaults to empty. `pkg/configuration/configuration.go`
- After alias, `ValidateParams` compiles `CaptchaFilePath` via `GetTemplate` when that field is non-empty. `pkg/configuration/configuration.go`
- `bouncer.New` passes `config.CaptchaFilePath` into `captcha.Client.New`, which compiles that path again and serves that template. `pkg/bouncer/bouncer.go`, `pkg/captcha/captcha.go`
- `TestHunt_captchaFilePathWinsOverDeprecatedHTMLPath` not found. No committed regression that both keys are set and the current path wins. `zzz_plugin_test.go`

## Desired
- Alias `captchaHtmlFilePath` onto `captchaFilePath` only when `captchaFilePath` is empty (same guard as ban).
- When both keys are set, compile and serve `captchaFilePath`.
- Add a regression test for that both-set case.
- Bound the ask to this defect only.

## Affected
- `plugin.go` (captcha alias `if`)
- A plugin-package regression test (likely `zzz_plugin_test.go`)

## Out of scope
- Removing or renaming `captchaHtmlFilePath`
- Changing the `/captcha.html` default
- Ban alias (already empty-guarded)
- Other hunt findings (empty captcha keys, siteverify, AppSec, CAPI)
- README / spec / usage-doc rewrites
- `captcha.Client.New` ignoring `GetTemplate` errors

## Unknowns
- Whether Traefik overlay ever leaves `CaptchaFilePath` as `""` when only the deprecated key is set (`CreateConfig` pre-fills the default).
- Whether the missing hunt test should keep the `TestHunt_` name or a durable plugin-package name.

## Tensions
- Ticket names `TestHunt_captchaFilePathWinsOverDeprecatedHTMLPath` as proven FAIL; that test is not on dest.
- Strict empty-guard plus a non-empty default means a deprecated-only deploy that never clears `captchaFilePath` keeps `/captcha.html`. Ticket still asks for the ban-shaped guard and bounds the defect to “when both are set, `captchaFilePath` wins.”
