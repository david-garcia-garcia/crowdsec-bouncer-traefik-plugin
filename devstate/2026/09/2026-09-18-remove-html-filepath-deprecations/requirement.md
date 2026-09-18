# Requirement
IssueKey: 2026-09-18-remove-html-filepath-deprecations

## Problem
Deprecated `banHtmlFilePath` and `captchaHtmlFilePath` still exist as Config fields and `plugin.New` aliases. Ban copies only when `BanFilePath` is empty; captcha copies whenever the old key is non-empty and overwrites `CaptchaFilePath`. The ticket wants those settings gone, with no compatibility alias.

## Current (code)
- `Config` has `BanHTMLFilePath` `json:"banHtmlFilePath,omitempty"` and `CaptchaHTMLFilePath` `json:"captchaHtmlFilePath,omitempty"`, both commented Deprecated. `pkg/configuration/configuration.go`
- Those two are the only `Deprecated` settings on `Config`. `pkg/configuration/configuration.go`
- `configuration.New` defaults `BanFilePath` to `""` and `CaptchaFilePath` to `/captcha.html`. It does not set the HTML-path fields. `pkg/configuration/configuration.go`
- `plugin.New` copies `BanHTMLFilePath` onto `BanFilePath` only when `BanFilePath` is empty. `plugin.go`
- `plugin.New` copies `CaptchaHTMLFilePath` onto `CaptchaFilePath` whenever `CaptchaHTMLFilePath` is non-empty (overwrites). `plugin.go`
- Template load and Content-Type inference read `BanFilePath` / `CaptchaFilePath` only. `pkg/configuration/configuration.go`
- Real e2e still sets `banHtmlFilePath` / `captchaHtmlFilePath` on Traefik labels. `tests/e2e/real/docker-compose.test.yml`
- Mock captcha scenario still sets `captchaHtmlFilePath`. `tests/e2e/mock/scenarios/captcha/dynamic.yml`
- Mock custom-ban scenario already sets `banFilePath`. `tests/e2e/mock/scenarios/custom-ban-page/dynamic.yml`
- Live OpenSpec custom-ban scenario still names `banHtmlFilePath`. `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md`
- Archived OpenSpec copy of that scenario still names `banHtmlFilePath`. `openspec/changes/archive/2026-09-05-add-real-e2e/specs/build_e2e_pester_crowdsec-stack/spec.md`
- No product Go test references `BanHTMLFilePath` / `CaptchaHTMLFilePath`. not found
- README does not name the old keys. `README.md`
- `examples/enhanced-decisions/traefik/crowdsec-bouncer.yml` is not on `origin/master`. not found
- In-tree custom-ban example already uses `banFilePath`. `examples/custom-ban-page/docker-compose.yml`

## Desired
- Delete `BanHTMLFilePath` and `CaptchaHTMLFilePath` from `Config` (fields, json tags, comments).
- Delete both `plugin.New` alias blocks. `New()` must not read the old keys.
- Operators configure `banFilePath` and `captchaFilePath` only. YAML that still sets the old keys must not be copied onto the current fields.
- Update in-tree e2e YAML, examples, live OpenSpec, README/docs, and tests that still name the old keys to `banFilePath` / `captchaFilePath`.
- Archived OpenSpec folders may keep historical names unless a live spec still requires the old key.
- Tests: no remaining product references to the old fields or json tags. Current keys still compile and serve. Do not add a new empty-guard alias test.

## Affected
- `pkg/configuration/configuration.go`
- `plugin.go`
- `tests/e2e/real/docker-compose.test.yml`
- `tests/e2e/mock/scenarios/captcha/dynamic.yml`
- `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md`

## Out of scope
- Template loading, Content-Type inference, and defaults for `BanFilePath` / `CaptchaFilePath`
- Other config knobs
- Rewriting archived OpenSpec history
- Reusing closed PR #85 or branch `2026-09-18-captcha-html-path-clobbers-file-path`
- Adding an empty-guard alias test

## Unknowns
- Whether Traefik mapstructure-decode errors or drops unknown YAML keys after the fields are gone is not proven in this tree. Ticket states unknown keys are ignored. `knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`

## Tensions
- Ban alias is empty-guard; captcha alias overwrites. Ticket wants both removed, not an empty-guard fix.
- Ticket lists `examples/enhanced-decisions/traefik/crowdsec-bouncer.yml` and README leftovers; dest has neither.
- Ticket lists live OpenSpec update; archive copy may keep `banHtmlFilePath`.
