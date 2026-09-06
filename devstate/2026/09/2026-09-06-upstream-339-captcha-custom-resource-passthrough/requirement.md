# Requirement
IssueKey: 2026-09-06-upstream-339-captcha-custom-resource-passthrough

## Problem

Custom captcha deployments (e.g. wicketkeeper via `captchaProvider=custom`) expose JS and challenge endpoints on the same bouncer-protected route. When an IP is captcha-flagged, requests for those asset paths (`/fast.js`, `/v0/challenge`) receive the captcha HTML page instead of the origin resources, so the challenge cannot load.

## Current (code)

- `pkg/configuration/configuration.go:115-118` — `CaptchaCustomJsURL`, `CaptchaCustomValidateURL`, `CaptchaCustomKey`, `CaptchaCustomResponse` exist; no `CaptchaCustomChallengeURL`.
- `pkg/configuration/configuration.go:469-475` — custom provider validation requires the four existing custom fields; challenge URL not validated.
- `pkg/bouncer/bouncer.go:277-288` — `handleRemediationServeHTTP` for captcha remediation only calls `handleNextServeHTTP` after `captchaClient.Check` (grace period); otherwise always `captchaClient.ServeHTTP` (captcha HTML).
- `pkg/captcha/captcha.go:69-70` — custom provider stores `js`/`validate` URLs in `infoProvider`; no challenge URL field.
- `pkg/captcha/captcha.go:110-113` — `CaptchaCustomJsURL` is embedded in the captcha template as `FrontendJS`; not used to bypass remediation for matching requests.
- `examples/custom-captcha/README.md:27-34` — documents `captchaCustomJsURL` pointing at `/fast.js`; template references `/v0/challenge` via `data-challenge-url` on the same host.
- `pkg/bouncer/bouncer_test.go` — no test for custom captcha asset pass-through on captcha-flagged IPs.

## Desired

- Add `CaptchaCustomChallengeURL` configuration for the custom captcha challenge endpoint (e.g. `/v0/challenge`).
- When remediation is captcha (not ban), pass matching requests through to origin for URLs configured as `CaptchaCustomJsURL` and `CaptchaCustomChallengeURL`.
- Banned IPs must still be blocked (no pass-through on ban remediation).

## Affected

- `pkg/configuration/configuration.go`
- `pkg/bouncer/bouncer.go`
- `pkg/captcha/captcha.go` (config wiring / URL matching if needed)
- `pkg/bouncer/bouncer_test.go` (new coverage)
- `examples/custom-captcha/` (document new option if required)

## Out of scope

- Changes to upstream maxlerebourg repo; this is a fork fix aligned with upstream#339.
- Pass-through for non-custom captcha providers (hcaptcha, recaptcha, turnstile use CDN URLs).
- Pass-through for `CaptchaCustomValidateURL` (server-side verify stays on plugin path).
- Grace-period `Check()` behavior change beyond asset URL matching.
- AppSec or live-lookup paths unrelated to captcha remediation.
- E2E wicketkeeper docker demo automation.

## Unknowns

- Exact URL matching semantics: path-only vs full URL equality vs prefix (ticket names config URLs but not match rules).
- Whether `CaptchaCustomChallengeURL` is required when custom provider is enabled or optional (wicketkeeper template uses inline challenge URL today).
- Whether pass-through should apply on HEAD requests (captcha branch skips HEAD today at `bouncer.go:281`).

## Tensions

- Assessment cites `examples/custom-captcha` challenge URL in HTML template, not config — new key may need example/README update to stay consistent.
- Ticket asks pass-through for captcha-flagged IPs only; ban path must remain blocked — implementation must not weaken ban handling.
- Upstream issue is a feature request; no existing tests define expected match behavior.
