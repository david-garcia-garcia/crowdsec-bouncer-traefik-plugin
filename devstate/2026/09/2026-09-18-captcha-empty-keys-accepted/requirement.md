# Requirement
IssueKey: 2026-09-18-captcha-empty-keys-accepted

## Problem
`ValidateParams` accepts a set `bouncerCaptchaProvider` when resolved site and secret keys are empty. The spec requires an error. The existing alone-mode test is a false positive.

## Current (code)
- `pkg/configuration/configuration.go` `validateCaptchaCredentials`: `GetVariable` on `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` returns only lookup errors; an empty resolved string is accepted.
- `pkg/configuration/configuration.go` `validateEnabledCaptchaSettings`: when `BouncerCaptchaProvider` is set, rejects empty `BouncerCaptchaGateSecret` and a missing template at `BouncerCaptchaFile`; does not reject empty site or secret after lookup.
- `pkg/configuration/configuration.go` `GetVariable`: file path then config field; empty field returns `""`, nil. No env lookup in this function.
- `pkg/configuration/configuration.go` `New` defaults: `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` `""`; `BouncerCaptchaFile` `/captcha.html`.
- `pkg/configuration/zzz_configuration_test.go` `Test_ValidateParams`: "Captcha LAPI action with provider" expects success with provider + gate secret and empty site/secret. "Alone mode captcha without site/secret keys" expects error but omits `BouncerCaptchaGateSecret` and keeps the default template path, so it fails on gate secret or the missing default template.
- `openspec/specs/core_plugin_middleware_config-validation/spec.md` scenario "Alone mode missing captcha keys": alone + captcha failure action + provider + empty site/secret → `ValidateParams` error.
- `plugin.go` `New`: `ValidateParams` failure returns `nil, err`. Hunt tests `TestHunt_newRejectsEnabledCaptchaWithoutSiteKey` and `TestHunt_ValidateParams_aloneMissingSiteKeysWithGateSecret`: not found.

## Desired
When `bouncerCaptchaProvider` is set, reject empty resolved `BouncerCaptchaSiteKey` and `BouncerCaptchaSecretKey` after file/field lookup, including alone mode when `BouncerCaptchaGateSecret` is set. `New` must not return a handler. Add regression tests. Bound to this defect only.

## Affected
- `pkg/configuration/configuration.go` (`validateCaptchaCredentials`)
- `pkg/configuration/zzz_configuration_test.go`
- `plugin.go` `New` (keep `nil` handler on validation error)

## Out of scope
- Empty `BouncerCaptchaGateSecret` (already rejected)
- Template and custom-challenge URL rules
- Captcha routing, gate, or provider HTTP
- Other `ValidateParams` rules
- A new env lookup beyond `GetVariable`

## Unknowns
- Hunt test names are not in this tree; implement adds equivalent regressions.
- Ticket says file/env lookup; `GetVariable` is file then config field only.

## Tensions
- "Captcha LAPI action with provider" currently asserts success without site/secret keys; the ticket requires that to become an error.
- "Alone mode captcha without site/secret keys" already wants error, but for gate secret / default template, not empty site/secret.
