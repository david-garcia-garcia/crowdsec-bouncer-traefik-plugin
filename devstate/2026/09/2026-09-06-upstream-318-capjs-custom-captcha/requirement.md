# Requirement
IssueKey: 2026-09-06-upstream-318-capjs-custom-captcha

## Problem
Operators configuring `captchaProvider=custom` with CapJS Standalone cannot verify solved challenges: the plugin rejects or fails verification because the outbound siteverify call uses the wrong HTTP body format for CapJS.

## Current (code)
- `pkg/configuration/configuration.go` — `CaptchaCustomJsURL`, `CaptchaCustomValidateURL`, `CaptchaCustomKey`, `CaptchaCustomResponse` configure the custom provider; validation requires all four when `CaptchaProvider=custom`.
- `pkg/captcha/captcha.go` — `Validate` reads the user response from `r.FormValue(c.infoProvider.response)` and always posts urlencoded `secret` + `response` via `httpClient.PostForm` to `infoProvider.validate`.
- `examples/custom-captcha/README.md` — documents Wicketkeeper only; states verify endpoint must accept `application/x-www-form-urlencoded`.
- `pkg/captcha/*_test.go` — not found (no tests for custom verify behavior).

## Desired
Configurable custom-captcha verification so CapJS Standalone works: allow the verify request to be generated in the format the provider expects (JSON `POST` with `secret` and `response` for CapJS `/siteverify`, while preserving current urlencoded behavior for Wicketkeeper-like providers).

## Affected
- Operators using `captchaProvider=custom` with CapJS or similar JSON siteverify APIs.
- `pkg/captcha/captcha.go` verify path.
- `pkg/configuration/configuration.go` if a new config knob is needed for verify body format.
- `examples/custom-captcha/README.md` documentation.

## Out of scope
- Built-in CapJS widget integration beyond existing custom JS/key/response knobs.
- Changes to hcaptcha/recaptcha/turnstile built-in providers.
- CapJS challenge generation or dashboard setup.
- External Bun proxy adapters (workaround, not product goal).

## Unknowns
- Exact config surface for body format (new enum vs auto-detect vs content-type knob) — explore/propose.
- Whether CapJS token field name always matches `CaptchaCustomResponse` or needs separate mapping.

## Tensions
- Ticket asks for "more control over how the CAPTCHA verification request is generated"; minimum fix is JSON vs form encoding, but extra fields or headers are not explicitly requested.
- Assessment cites upstream reporter using an external adapter; product should remove that need without requiring sidecar proxies.
- README currently documents urlencoded-only requirement; may mislead CapJS users until updated.
