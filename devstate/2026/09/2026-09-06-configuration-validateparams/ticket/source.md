# ValidateParams skips AppSec TLS/URL checks, alone-mode captcha/template/log checks, and several mode tests

## Problem

`ValidateParams` has holes that let a broken plugin start:

1. AppSec URL validation uses `CrowdsecLapiScheme`; AppSec HTTPS/TLS is never checked.
2. `alone` mode returns before captcha keys, templates, and log checks.
3. Missing tests for custom captcha provider, AppSec captcha gate, `appsec`/`none`/`alone` modes, `GetTemplate`, `validateURL`, numeric bounds.

Do **not** re-do captcha empty-template-path / `GetTemplate` swallow in `pkg/captcha` — that is ticket `2026-09-06-captcha-handler-hardening`. You may still require template presence in ValidateParams for non-captcha-package paths (alone-mode early return) if that is not already covered there.

## Evidence

Sibling files: `appsec-validation-gaps.md`, `alone-mode-short-circuits-validation.md`, `failure-action-and-mode-coverage-gaps.md`. Skip implementing `captcha-template-validation-gaps.md` except the alone-mode short-circuit overlap.

## Current behavior

AppSec can be HTTPS-misconfigured while LAPI HTTP validates. Alone mode skips later validation. Several modes and helpers have no tests.

## Desired

Validate AppSec URL and TLS against AppSec fields, not LAPI scheme. Do not return early in alone mode before captcha/template/log checks that still apply. Add the missing ValidateParams tests listed in the coverage finding.

## Grouped with this file

- appsec-validation-gaps
- alone-mode-short-circuits-validation
- failure-action-and-mode-coverage-gaps

## Out of scope

`captcha-template-validation-gaps` runtime panic in `pkg/captcha` (other ticket). Ban-template swallow in `bouncer.New` (bouncer ticket).

---

## appsec-validation-gaps

AppSec URL and TLS checks in ValidateParams use LAPI settings or are omitted.

Operators can configure AppSec on a different scheme or TLS trust material than LAPI, but `ValidateParams` either validates AppSec with the LAPI scheme or skips AppSec TLS entirely.

Evidence:
- pkg/configuration/configuration.go:339 — `validateURL("CrowdsecAppsec", config.CrowdsecLapiScheme, ...)` passes LAPI scheme, not AppSec scheme.
- pkg/configuration/configuration.go:378-383 — `validateParamsTLS` runs only when `CrowdsecLapiScheme == HTTPS`.
- pkg/configuration/configuration.go:438-452 — `validateParamsTLS` reads only LAPI CA fields.
- pkg/appsec/client.go:38-40 — runtime fills empty AppSec scheme from LAPI scheme after validation.

Desired: Validate AppSec using effective scheme (`CrowdsecAppsecScheme` when set, otherwise `CrowdsecLapiScheme`) and parse AppSec CA/client cert material when HTTPS and insecure verify is false.

## alone-mode-short-circuits-validation

In `crowdsecMode: alone`, `ValidateParams` validates CAPI credentials then returns immediately. Captcha secrets, ban/captcha template files, log level, and log file writability are never checked.

Evidence:
- pkg/configuration/configuration.go:306-313 — alone branch returns before captcha/template/log checks.
- plugin.go:35-39 — ValidateParams still invoked for alone mode.

Desired: Run captcha credential/template validation, ban template validation, and logging validation for alone mode. Add alone-mode tests.

Out of scope: Skipping LAPI URL/LAPI key/TLS validation in alone mode after CAPI credential checks.

## failure-action-and-mode-coverage-gaps

Several validation branches have no direct unit tests.

Desired tests: `validateCaptcha` custom provider missing fields; AppSec failure action `captcha` without provider; `ValidateParams` success for `appsec` mode without LAPI key; `GetTemplate` error paths; `validateURL` with bad host/path; `RemediationStatusCode` 99/600; `UpdateMaxFailure: -1` acceptance.

Out of scope: `LogFormat` fallback; header custom name RFC validation.
