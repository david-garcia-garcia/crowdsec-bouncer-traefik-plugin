# Requirement
IssueKey: 2026-09-18-captcha-verify-template-ux

## Problem
Three leftovers on dest captcha: siteverify omits bouncer-resolved `remoteip`; transport and JSON-decode errors become bare HTTP 400; an empty `CaptchaFilePath` with a provider set is accepted and `Client.New` discards `GetTemplate` error.

## Current (code)
- `Validate(r)` posts `secret` and `response` only. No `remoteip`. Signature has no `remoteIP`. Path: `pkg/captcha/captcha.go`.
- Captcha does not read `X-Forwarded-For`. Path: `pkg/captcha/` (not found).
- Bouncer already passes resolved `req.remoteIP` into `ServeHTTP(rw, r, remoteIP)`. Path: `pkg/bouncer/bouncer.go`.
- `PostForm` error returns `(false, err)`. JSON `Decode` error returns `(false, err)`. Path: `pkg/captcha/captcha.go`.
- `ServeHTTP` on `err != nil` logs and writes HTTP 400 with no body. Path: `pkg/captcha/captcha.go`.
- Empty token, `success:false`, and non-JSON Content-Type return `(false, nil)` and re-render captcha HTML at 200. Content-Type uses `mime.ParseMediaType` and `mediaType != "application/json"`. Path: `pkg/captcha/captcha.go`.
- On `valid`, `mintGateValue` / `setGateCookie` then 302. Path: `pkg/captcha/captcha.go`, `pkg/captcha/gate.go`.
- `cache.Client.Set` is void. Path: `pkg/cache/cache.go`.
- `Client.New` has no `cacheClient`. `GetTemplate` error discarded (`_`). Always `return nil`. Path: `pkg/captcha/captcha.go`.
- `bouncer.New` already returns `captcha.Client.New` error. Path: `pkg/bouncer/bouncer.go`.
- Default `CaptchaFilePath` is `/captcha.html`. Path: `pkg/configuration/configuration.go`.
- `GetTemplate("")` errors `no template file provided`. Path: `pkg/configuration/configuration.go`.
- `validateEnabledCaptchaSettings`: provider set + `CaptchaFilePath == ""` returns nil; non-empty path runs `GetTemplate` and fails on read/parse. Path: `pkg/configuration/configuration.go`.
- Test "Captcha LAPI action with provider" expects success with empty `CaptchaFilePath`. Several captcha tests blank the path to skip template load. Path: `pkg/configuration/zzz_configuration_test.go`.
- Siteverify spec owns JSON Content-Type and cookie+302 on `success` true. No `remoteip`. No transport/decode 200 rule. Path: `openspec/specs/core_plugin_middleware_captcha-siteverify/spec.md`.
- Config spec validates captcha/ban templates "when paths are set". Path: `openspec/specs/core_plugin_middleware_config-validation/spec.md`.
- Gate cookie spec: solve → `crowdsec_captcha_gate` then 302. Path: `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`.
- Empty-path panic already noted as debt from another ticket. Path: `knowledge/debt/2026-09-18-captcha-nil-template-panic.md`.

## Desired
1. Thread bouncer `remoteIP` into `Validate(r, remoteIP)` and add form field `remoteip` with `secret` and `response`. Do not re-parse forwarded headers in captcha.
2. Transport errors and JSON decode failures: log and re-render captcha HTML at HTTP 200. Do not bare-400 those. Keep `(false, nil)` for empty token, `success:false`, and non-JSON Content-Type.
3. When `CaptchaProvider` is set, `ValidateParams` fails if `CaptchaFilePath` is empty or `GetTemplate` fails. `Client.New` returns the `GetTemplate` error. No bundled template.
Keep dest grace cookie, void `cache.Set`, #94 Content-Type rule, and `Client.New` without cache.

## Affected
- `pkg/captcha/captcha.go` (`Validate` signature and body, error returns, `New`)
- `pkg/configuration/configuration.go` (`validateEnabledCaptchaSettings` empty-path early return)
- Captcha and configuration tests that blank `CaptchaFilePath` or assert 400 on provider errors
- Specs `core_plugin_middleware_captcha-siteverify` and `core_plugin_middleware_config-validation`

## Out of scope
- `cache.Client.Set` API; Redis `set` error handling; `remoteIP+_captcha` grace
- Gate cookie format, Secure, `CaptchaGateSecret`, bind-IP
- Revert Content-Type to `strings.Contains`; add `cacheClient` to `Client.New`
- Bundled default template; HTML-path deprecation (#100)
- LAPI, AppSec, Range, Redis TTL; `traefik-modsecurity`
- Closed PR #28 / branch `2026-09-06-captcha-handler-hardening`
- Siteverify HTTP status on a received body (other ticket)

## Unknowns
- Official hCaptcha / reCAPTCHA / Turnstile `remoteip` contract is not in `knowledge/research/` (indexes consumed; no Task write this phase). Ticket names the field.
- Tests that blank `CaptchaFilePath` to skip `GetTemplate` will need a real file once empty path is rejected.

## Tensions
- Config spec says validate templates "when paths are set"; ticket requires fail on empty path when provider is set.
- "Captcha LAPI action with provider" and custom-challenge tests expect success with empty `CaptchaFilePath`.
- Debt `knowledge/debt/2026-09-18-captcha-nil-template-panic.md` already records leftover 3; this ticket takes that leftover.
- Owner declined #28 because it replaced the gate cookie with cache Set. Do not regress dest cookie.
