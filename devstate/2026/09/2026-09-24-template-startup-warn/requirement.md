# Proposal: warn when captcha or ban templates are missing

IssueKey: 2026-09-24-template-startup-warn

A bouncing router must start even when the captcha page or the ban page cannot be loaded. Startup logs a warning. Captcha remediation falls back to ban. Ban remediation stays a status with an empty body.

This is the ask. It is not an implementation.

## Problem

bouncerDecisionHeader value b (and every other ban) returns the remediation status, default 403, with an empty body when bouncerBanFilePath is empty. ban.html in the repository is a sample. The plugin does not load it unless that path points at a file Traefik can read.

A missing or unreadable captcha template does the opposite: middleware New fails, so the route never runs.

## Desired

Check both files when the bouncer is created. Do not fail New for either file. Do not invent a bundled default page.

Captcha file empty or not loadable. Warn once at startup that captcha responses will fall back to ban. A captcha remediation then uses the ban path. This replaces today's hard failure. Site key, secret, and gate secret stay required when a captcha provider is set.

Ban file empty or not loadable. Warn once at startup that no ban file is available, or that the configured path could not be loaded, and that ban responses are served without a body. Keep the empty body. HEAD stays bodyless even when a template loads.

The warning is startup-only. Do not repeat it on every request.

## Current

- pkg/configuration/configuration.go BouncerBanFilePath defaults to empty. CaptchaFilePath defaults to /captcha.html.
- validateEnabledCaptchaSettings returns an error when captcha is enabled, a provider is set, and CaptchaFilePath is empty or GetTemplate fails. Error text today: CaptchaFilePath: cannot be empty when CaptchaProvider is set.
- validateCaptchaCredentialsAndTemplates returns the GetTemplate error when BouncerBanFilePath is set and the file cannot be loaded. An empty ban path is accepted with no warning.
- pkg/captcha/captcha.go Client.New returns the GetTemplate error and does not leave Valid false.
- pkg/bouncer/bouncer.go New loads the ban template only when the path is non-empty and discards the GetTemplate error. handleBanServeHTTP writes the status and returns without a body when banTemplate is nil.
- handleRemediationServeHTTP already bans when the captcha client is nil or Valid is false, and warns crowdsec bouncer captcha unsubscribed only when the router never subscribed.

Live contract that must change: openspec/specs/core_plugin_middleware_config-validation/spec.md (provider-set captcha template fails ValidateParams and Client.New; empty ban path is silent). Usage note with the same rule: knowledge/devdocs/core_plugin_middleware_config-validation.md.

## Out of scope

- Embedding ban.html or captcha.html into the plugin.
- Changing the remediation status code.
- Relaxing site key, secret, or gate secret checks.
- A per-request warning for a missing template.
- Creating a CrowdSec decision from bouncerDecisionHeader.

## Open point

The captcha file is loaded by the captcha client (captcha.Client.New / captcha.Open). The ban file is loaded by the bouncer (bouncer.New). A bounce-only router does not own captchaFilePath. Explore must say whether the captcha warning is emitted by the captcha instance that fails to load the file, by the bouncer at creation, or by both, without a false warning on a subscriber whose own path is the unused default /captcha.html.

## Current (code)

Spec `## Current` is the dest contract. Extra dest facts that section does not already state:

- `pkg/configuration/configuration.go` `ValidateParams` calls `validateCaptchaCredentialsAndTemplates`. `validateEnabledCaptchaSettings` returns immediately when `CaptchaEnabled` is false, so a bounce-only subscriber does not `GetTemplate` its unused default `/captcha.html`.
- `pkg/configuration/configuration.go` `GetTemplate("")` returns `no template file provided`. `BouncerRemediationStatusCode` defaults to 403.
- `plugin.go` `New` returns `nil, err` on `ValidateParams` failure before `openOwned`. `openOwnedLeg` calls `captcha.Open` only when `CaptchaEnabled`. `subscribeCaptcha` is `BouncerEnabled` plus a non-empty `CaptchaInstanceName`.
- `pkg/captcha/session.go` `Open` → `newOwnerClient` → `Client.New(..., cfg.CaptchaFilePath, ...)`.
- `pkg/bouncer/bouncer.go` `New` does not read `CaptchaFilePath`. `handleBanServeHTTP` also returns without a body on HEAD when a template is loaded.
- `zzz_plugin_test.go` `TestNew_RejectsEmptyCaptchaFilePath` and `pkg/configuration/zzz_configuration_test.go` `Test_ValidateParams_captchaTemplateRequired` pin today's hard fail. `pkg/captcha/zzz_siteverify_test.go` `Test_New_returnsGetTemplateError` pins `Client.New`.
- `ban.html` at repo root is a sample. The plugin does not load it unless `BouncerBanFilePath` points at a readable file.

## Out of scope

Same list as the spec `## Out of scope`. No extras inferred.

## Affected

- `pkg/configuration/configuration.go` — `ValidateParams`, `validateEnabledCaptchaSettings`, `validateCaptchaCredentialsAndTemplates`, `GetTemplate`
- `pkg/captcha/captcha.go` — `Client.New`
- `pkg/captcha/session.go` — `Open` / `newOwnerClient`
- `pkg/bouncer/bouncer.go` — `New`, `handleBanServeHTTP`, `handleRemediationServeHTTP`
- `plugin.go` — `New` / `openOwned`
- `openspec/specs/core_plugin_middleware_config-validation/spec.md`
- `knowledge/devdocs/core_plugin_middleware_config-validation.md`

## Unknowns

- Spec `## Open point`: who emits the captcha-template warning (captcha instance, bouncer at creation, or both) without a false warning on a subscriber whose own path is the unused default `/captcha.html`.
- Exact warning text.
- Whether `Client.New` leaving `Valid` false (so the existing ban fallback fires) is enough, or the owner must stay `Valid` and the ban path is chosen elsewhere. Explore owns that. The ticket does not pick it.

## Tensions

- Ticket Desired: "Check both files when the bouncer is created." Dest: captcha file is loaded by `captcha.Client.New` / `captcha.Open` (`pkg/captcha/session.go`); `bouncer.New` does not own `CaptchaFilePath`. Same split the Open point names.
- Ticket Desired: do not fail `New` for a missing captcha file. Live spec `openspec/specs/core_plugin_middleware_config-validation/spec.md` and usage `knowledge/devdocs/core_plugin_middleware_config-validation.md` require `ValidateParams` and `Client.New` to fail. The ticket already names those as the contract that must change.
