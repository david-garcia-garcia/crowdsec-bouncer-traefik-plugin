## Context

`ValidateParams` runs in `plugin.go` before `lapi.Prepare` / `appsec.Prepare` rewrite endpoints. AppSec scheme fallback at runtime is intentional; validation must use the same effective scheme contract.

## Goals / Non-Goals

**Goals:**
- Fail fast on AppSec HTTPS misconfiguration (URL scheme, CA PEM).
- Run captcha/template/logging validation in alone mode.
- Cover missing test branches.

**Non-Goals:**
- Fix runtime captcha nil-template panic (`pkg/captcha` ticket).
- Ban-template swallow in `bouncer.New`.
- Parse AppSec client cert pairs at ValidateParams (runtime handles via `GetTLSConfigCrowdsec`).

## Decisions

1. **Effective AppSec scheme** — inline helper: `appsecScheme := config.CrowdsecAppsecScheme; if appsecScheme == "" { appsecScheme = config.CrowdsecLapiScheme }`.
2. **AppSec TLS** — parameterize `validateParamsTLS` with prefix string (`CrowdsecLapi` / `CrowdsecAppsec`). Run AppSec branch only when `CrowdsecAppsecScheme != ""` and HTTPS with verify enabled (matches `GetTLSConfigCrowdsec` prefix selection).
3. **Alone mode** — extract shared captcha/template block before mode branch; alone validates CAPI then `continue` pattern via `if alone { ... } else { lapi block }`; log checks after both branches.
4. **Tests** — extend existing table tests; add `Test_validateCaptcha`, `Test_validateURL`, `Test_GetTemplate` error paths.

## Risks / Trade-offs

- Alone mode with AppSec enabled still skips AppSec URL/TLS (unchanged; alone uses CAPI for decisions). Acceptable per requirement out-of-scope for LAPI skips.

## Migration Plan

None — stricter validation may reject configs that previously started; intended bugfix.
