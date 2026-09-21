# Devdocs impact
change: remove-html-filepath-deprecations

## Units
- Middleware New — subsystem — `plugin.go` / `knowledge/devdocs/core_plugin_middleware.md`
- Real-stack e2e — subsystem — `tests/e2e/real/` / `knowledge/devdocs/build_e2e_real.md` / `openspec/specs/build_e2e_pester_crowdsec-stack`
- Mock LAPI e2e — subsystem — `tests/e2e/mock/` / `knowledge/devdocs/build_e2e_mock.md`

## Findings
- [x] stale-usage  Middleware New — How-to snapshots `prepared` but does not say `New` must not reconstruct `BouncerBanFile` / `BouncerCaptchaFile` from leftover YAML keys
- [x] stale-usage  Real-stack e2e — custom-ban / captcha compose labels now require `bouncerBanFile` / `bouncerCaptchaFile`; packet still silent
- [x] stale-usage  Mock LAPI e2e — captcha scenario now requires `bouncerCaptchaFile`; packet still silent
