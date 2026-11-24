# WAF failure-action captcha downgrade shows reason `LAPI`

IssueKey: 2026-11-23-backoff-action-per-leg
Size: large
Action: note

## Why this follow-up

`captchaAppsecFailure` and `captchaModsecFailure` call `handleRemediationServeHTTP`, which passes `configuration.ReasonLAPI` as the ban-template reason to `handleCaptchaKindServeHTTP`. When the captcha client is unusable and the captcha downgrades to a ban, the ban page gets `{{ .RemediationReason }}` = `LAPI` for an AppSec or ModSec failure instead of `APPSEC` / `MODSEC`.

## Why it was not taken

Pre-existing behaviour outside the ask. Changing it alters an operator-visible template value on the failure paths and their tests. The backoff paths this change adds pass their own leg reason, so the asymmetry is not widened.

## Risks

A ban page or log built on `RemediationReason` misattributes a WAF outage to LAPI in the downgrade case.

## Context

`pkg/bouncer/bouncer_serve_remediation.go:20-27`, `pkg/bouncer/bouncer_serve_appsec.go:111-116`, `pkg/bouncer/bouncer_serve_modsec.go:77-82`.
