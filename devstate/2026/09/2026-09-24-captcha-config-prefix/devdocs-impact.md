# Devdocs impact
change: captcha-config-prefix

## Units
- Config validation — subsystem — `pkg/configuration/configuration.go`, spec `core_plugin_middleware_config-validation`
- Middleware New — subsystem — `plugin.go` / `pkg/captcha/session.go`, spec `core_plugin_middleware_bouncer`
- Captcha gate cookie — subsystem — `pkg/captcha`, spec `core_plugin_middleware_captcha-gate`
- Captcha request routing — subsystem — `knowledge/devdocs/core_plugin_middleware_captcha-routing.md`
- Captcha siteverify — subsystem — `knowledge/devdocs/core_plugin_middleware_captcha-siteverify.md`
- OriginBasedDecisionRemap — subsystem — `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md`
- LAPI reclaim key — subsystem — spec `core_plugin_lapi_reclaim-key`
- Real-stack e2e — subsystem — `build_e2e_real.md`, spec `build_e2e_pester_crowdsec-stack`
- Mock LAPI e2e — subsystem — `build_e2e_mock.md`

## Findings
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` still names `BouncerCaptcha*` / `bouncerCaptcha*` in Language, How-to, snippet, and Gotchas
- [x] stale-usage  Middleware New — `core_plugin_middleware` still copies leftover keys into `BouncerCaptchaFilePath` and times out from `BouncerCaptchaSiteverifyHTTPTimeoutSeconds`
- [x] language-gap  Captcha gate cookie — `core_plugin_middleware_captcha-gate` Language still signs with `bouncerCaptchaGateSecret` and `_Avoid_`s the live key `captchaGateSecret`
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` Gotcha still says `bouncerCaptchaCustomChallengeUrl`
- [x] stale-usage  Captcha siteverify — `core_plugin_middleware_captcha-siteverify` How-to still fills `validateBody` from `BouncerCaptchaCustomValidateBody`
- [x] stale-usage  OriginBasedDecisionRemap — `core_plugin_lapi_origin-based-decision-remap` still says do not require `bouncerCaptchaProvider`
- [x] stale-usage  Real-stack e2e — `build_e2e_real` compose labels still use `bouncerCaptchaFilePath` / `bouncerCaptchaProvider`
- [x] stale-usage  Mock LAPI e2e — `build_e2e_mock` scenarios still use `bouncerCaptchaFilePath` / `bouncerCaptchaProvider`
