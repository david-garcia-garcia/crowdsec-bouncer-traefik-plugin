# Requirement
IssueKey: 2026-09-06-upstream-380-trycap-captcha

## Problem
Operators who self-host [TryCap Cap Standalone](https://trycap.dev/guide/standalone/) cannot use it as a first-class captcha provider in this Traefik bouncer plugin. They must run an external adapter or misconfigure the `custom` provider, because verification semantics differ from what the plugin implements today.

## Current (code)
- `pkg/configuration/configuration.go` — `CaptchaProvider` accepts `hcaptcha`, `recaptcha`, `turnstile`, or `custom` only (`validateCaptcha`); no `trycap` constant or TryCap-specific config fields.
- `pkg/captcha/captcha.go` — built-in `infoProviders` maps the three SaaS providers to fixed JS URLs, HTML class keys, form field names, and validate URLs; `custom` fills those from `CaptchaCustom*` config at init.
- `pkg/captcha/captcha.go` — `Validate` always reads `r.FormValue(c.infoProvider.response)` and verifies via `httpClient.PostForm` with urlencoded `secret` and `response` (`PostForm` at lines 143–146).
- `pkg/captcha/captcha.go` — template render passes `FrontendJS`, `FrontendKey`, and `SiteKey` only; no TryCap `data-cap-api-endpoint` or instance URL slot.
- `captcha.html` — widget div uses `class="{{ .FrontendKey }}" data-sitekey="{{ .SiteKey }}"`; incompatible with Cap widget’s `data-cap-api-endpoint` + `cap-token` field model.
- `examples/custom-captcha/README.md` — documents Wicketkeeper (urlencoded siteverify) only; no TryCap example.
- `pkg/captcha/` — no `*_test.go` covering provider validate behavior.
- `tests/e2e/real/captcha.Tests.ps1`, `tests/e2e/mock/scenarios/captcha/run.sh` — e2e captcha flows exist but do not exercise TryCap.

## Desired
Add first-class TryCap (Cap Standalone) support alongside hcaptcha/recaptcha/turnstile: operator selects a built-in TryCap provider, supplies instance URL + site/secret keys, the captcha page loads the Cap widget against that instance, and server-side verification POSTs JSON `{"secret","response"}` to `https://<instance>/<site_key>/siteverify`, reading the `cap-token` form field — matching Cap Standalone docs. Include tests proving the verify path.

## Affected
- `pkg/configuration/configuration.go` — provider enum, validation, new config surface for instance URL if needed.
- `pkg/captcha/captcha.go` — TryCap provider registration, JSON verify path, template data for widget endpoint.
- `captcha.html` and/or provider-specific template handling — Cap widget markup.
- `pkg/bouncer/bouncer.go` — wires captcha init from config (may need new config fields passed through).
- Tests under `pkg/captcha/` and/or e2e captcha scenarios.

## Out of scope
- Generic JSON body support for the existing `custom` provider (upstream #318 / CapJS) unless required as shared machinery for TryCap only.
- Documenting or supporting captcha providers beyond TryCap in this change.
- Shipping or deploying a Cap Standalone container (operator-owned infrastructure).
- Upstream issue closure or PR to maxlerebourg/crowdsec-bouncer-traefik-plugin.

## Unknowns
- Whether TryCap widget JS is loaded from the instance (`/<site_key>/` path) or a fixed CDN — Cap docs say set `data-cap-api-endpoint` to `https://<instance>/<site_key>/`; exact script tag pattern not verified in-tree.
- Whether instance URL belongs in a dedicated config key (e.g. `captchaTrycapInstanceUrl`) or can reuse an existing custom URL field without operator confusion.
- Whether default `captcha.html` can serve all providers or TryCap needs a separate template file.

## Tensions
- Ticket asks for parity “like hcaptcha, recaptcha etc.” but TryCap is self-hosted: validate URL is derived from instance URL + site key, not a fixed global endpoint like the three SaaS providers.
- Assessment notes same urlencoded-vs-JSON gap as upstream #318; fixing TryCap alone may duplicate work if a shared JSON verify path would serve both.
- Default `captcha.html` assumes class-based widget embedding (`FrontendKey`); Cap uses `cap-token` hidden field and `data-cap-api-endpoint`, so template symmetry with hcaptcha/recaptcha/turnstile is incomplete.
- No unit tests exist for any captcha provider verify behavior today; adding TryCap tests establishes new coverage baseline not present on `master`.
