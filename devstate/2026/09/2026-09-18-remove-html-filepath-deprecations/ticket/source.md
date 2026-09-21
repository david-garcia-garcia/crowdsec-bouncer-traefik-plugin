REMOVE the deprecated HTML-path settings completely. Do not keep a compatibility alias.

From #325 (2026-06-28): banHtmlFilePath and captchaHtmlFilePath were renamed to bouncerBanFile and bouncerCaptchaFile because templates are no longer HTML-only (JSON ban pages, GetTemplate, infer Content-Type). The old keys stayed as Deprecated fields "for historical compatibility".

Current master:
- pkg/configuration/configuration.go Config has BanHTMLFilePath json:banHtmlFilePath and CaptchaHTMLFilePath json:captchaHtmlFilePath, both marked Deprecated.
- plugin.New aliases: ban copies BanHTMLFilePath onto BouncerBanFile only when BouncerBanFile is empty; captcha copies CaptchaHTMLFilePath onto BouncerCaptchaFile whenever CaptchaHTMLFilePath is non-empty (overwrites).
- These are the only Deprecated settings on Config. No other alias knobs.
- In-tree leftovers still use the old keys: tests/e2e/real/docker-compose.test.yml, tests/e2e/mock/scenarios/captcha/dynamic.yml, examples/enhanced-decisions/traefik/crowdsec-bouncer.yml, openspec/specs/build_e2e_pester_crowdsec-stack/spec.md.

Desired:
- Delete BanHTMLFilePath and CaptchaHTMLFilePath from Config (fields + json tags + comments).
- Delete both plugin.New alias blocks. New() must not read the old keys.
- Operators configure bouncerBanFile and bouncerCaptchaFile only. A YAML that still sets banHtmlFilePath or captchaHtmlFilePath is ignored by Traefik (unknown keys) and must not be copied onto the current fields.
- Update in-tree e2e YAML, examples, live OpenSpec, README/docs, and tests that still name the old keys so they use bouncerBanFile / bouncerCaptchaFile.
- Archived OpenSpec change folders may keep historical names; do not rewrite archive history unless a live spec still requires the old key.
- Tests: no remaining product references to BanHTMLFilePath / CaptchaHTMLFilePath / the old json tags. Current keys still compile and serve. Do not add a new empty-guard alias test — the fields must be gone.

Bound the ask to removing these two deprecated settings and their aliases. Do not change template loading, Content-Type inference, defaults for BouncerBanFile / BouncerCaptchaFile, or other config knobs.
