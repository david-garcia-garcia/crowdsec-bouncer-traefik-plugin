## Why

A request that cannot solve a captcha gets the captcha HTML page with HTTP 200 whenever a captcha applies to it. The case that started this: a machine-to-machine API client behind an address that fell under a wide CrowdSec `captcha` decision (a whole AS). The client took the HTML for an API response. Today the operator can exempt the address from everything (`bouncerClientTrustedIps`), soften one origin on a whole router (`bouncerOriginBasedDecisionRemap`), or skip LAPI on the path (`bypassLapi`, which also drops the bans). Nothing says "on these requests, never a captcha, bans still apply".

## What Changes

- New `bouncerActionRules` action token `bypassCaptcha`. On a matching request, wherever this router would have served its captcha gate, the request continues instead. The LAPI lookup and the AppSec query still run, so bans still apply.
- Covered captcha sources: a CrowdSec `captcha` decision, an AppSec `captcha` verdict, the LAPI and AppSec failure action `captcha`, and a captcha form POST AppSec let through. A router with no usable captcha (where a captcha is a ban today) also lets the request through.
- A ban that `bouncerOriginBasedDecisionRemap` softens to a captcha stays a ban on these requests.
- `captcha` and `bypassCaptcha` in one rule fail validation. When another matching rule carries `captcha`, `bypassCaptcha` wins.
- Not covered: bans, the AppSec bot-detection `challenge`, any other AppSec action.
- A `bypassCaptcha` rule with a `path` applies its regex as written. It does not use the single-reading path check of `bypass`, `bypassLapi` and `bypassAppsec` (caller decision). The README states which path forms Traefik resolves before the plugin runs and which it does not by default.
- **Not BREAKING.** A configuration that does not use the token behaves as before.

## Capabilities

### Modified Capabilities

- `core_plugin_middleware_bouncer`: new requirement "bypassCaptcha lets a request through where a captcha would be served"; "Action rules fold every matching row" names the token, the `captcha` conflict, and the captcha-bypass flag.
- `core_plugin_middleware_config-validation`: "Invalid action rules fail ValidateParams" gains the `captcha` with `bypassCaptcha` stem.
- `core_plugin_lapi_origin-based-decision-remap`: new requirement "A ban-to-captcha edge does not apply on a captcha-bypass request".

## Impact

- `pkg/httprule/action.go` (token, `compileActionTokens`, `ActionMatch.BypassCaptchaName`, `Fold`)
- `pkg/bouncer/bouncer_serve_captcha.go`, `bouncer_serve_lapi.go`, `bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`, `origin_based_decision_remap.go`
- Tests: `pkg/httprule/zzz_httprule_test.go`, `pkg/configuration/zzz_configuration_test.go`, a new `pkg/bouncer` test file for the bypass
- `README.md` (new section for API routes, `BouncerActionRules` reference), devdocs `core_plugin_httprule.md` and `core_plugin_middleware_action-rules.md`
- `knowledge/research/ext_traefik_entrypoints_request-path/` (written in explore)
