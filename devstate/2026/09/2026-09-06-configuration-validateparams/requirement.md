# Requirement
IssueKey: 2026-09-06-configuration-validateparams

## Problem
`ValidateParams` in `pkg/configuration` lets misconfigured plugins start: AppSec URL/TLS is validated against LAPI settings or skipped; `alone` mode returns before captcha, template, and log checks that still apply at runtime; several validation branches lack unit tests.

## Current (code)
- `pkg/configuration/configuration.go:339` — AppSec URL validated with `CrowdsecLapiScheme`, not `CrowdsecAppsecScheme` (nor LAPI fallback).
- `pkg/configuration/configuration.go:378-383` — TLS validation runs only when `CrowdsecLapiScheme == HTTPS`; no AppSec HTTPS branch.
- `pkg/configuration/configuration.go:438-452` — `validateParamsTLS` parses only `CrowdsecLapiTLSCertificateAuthority`; AppSec CA fields ignored.
- `pkg/appsec/client.go:38-40` — runtime fills empty AppSec scheme from LAPI after validation passes.
- `pkg/configuration/configuration.go:306-313` — `AloneMode` returns after CAPI credential checks, skipping captcha/template/log validation at `316-333` and `385-395`.
- `pkg/configuration/configuration.go:464-479` — `validateCaptcha` enforces custom-provider fields; no dedicated test.
- `pkg/configuration/configuration.go:135-146` — `validateFailureAction` gates captcha on provider; AppSec captcha-without-provider path untested in `configuration_test.go`.
- `pkg/configuration/configuration.go:361-362` — `appsec` mode waives LAPI key requirement; no test.
- `pkg/configuration/configuration.go:261-276` — `GetTemplate` error paths untested.
- `pkg/configuration/configuration.go:417-423` — `validateURL` untested directly.
- `pkg/configuration/configuration_test.go:86-152` — no alone/appsec/none mode cases; no AppSec scheme/TLS cases.

## Desired
- Validate AppSec URL using effective scheme (`CrowdsecAppsecScheme` if set, else `CrowdsecLapiScheme`).
- When effective AppSec scheme is HTTPS and insecure verify is false, parse AppSec CA/client cert material like LAPI HTTPS today.
- Do not return from `AloneMode` before captcha credential/template, ban template, and logging checks that still apply.
- Add focused tests: custom captcha provider missing fields; AppSec `captcha` failure action without provider; `appsec` mode without LAPI key; alone mode with captcha failure-action and missing secrets/templates; `GetTemplate` error paths; `validateURL` bad host/path; `RemediationStatusCode` 99/600; `UpdateMaxFailure: -1`.

## Affected
- `pkg/configuration/configuration.go` — `ValidateParams`, `validateParamsTLS`, `validateURL`, possibly shared check ordering.
- `pkg/configuration/configuration_test.go` — new/extended unit tests.

## Out of scope
- Runtime panic / nil-template swallow in `pkg/captcha` (`2026-09-06-captcha-handler-hardening`).
- Ban-template swallow in `bouncer.New` (bouncer ticket).
- Skipping LAPI URL/key/TLS validation in alone mode after CAPI checks (intentional; `lapi.Prepare` rewrites endpoints).
- Cosmetic `validateURL` error prefix using LAPI scheme name for AppSec.
- `LogFormat` fallback in `pkg/logger/logger.go`; RFC 7230 header token validation.

## Unknowns
- Whether AppSec client cert fields (`CrowdsecAppsecTLSCertificateBouncer*`) need the same startup parse as LAPI bouncer certs, or CA-only parity is enough for this ticket.

## Tensions
- Ticket asks for template validation in alone mode; captcha runtime panic fix is explicitly another ticket — ValidateParams should reject missing/invalid templates without fixing `pkg/captcha` serve paths.
- AppSec scheme fallback at runtime in `appsec.Prepare` is intentional; validation must mirror that contract, not duplicate runtime logic verbatim.
