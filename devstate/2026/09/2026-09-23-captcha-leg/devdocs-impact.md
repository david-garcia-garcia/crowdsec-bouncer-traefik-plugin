# Devdocs impact
change: captcha-leg

## Units
- Plugin middleware New — subsystem — `plugin.go` / `knowledge/devdocs/core_plugin_middleware.md`
- Instance slots — subsystem — `knowledge/devdocs/core_plugin_middleware_instance-slots.md`
- Config validation — subsystem — `pkg/configuration` / `knowledge/devdocs/core_plugin_middleware_config-validation.md`
- Captcha Client — subsystem — `pkg/captcha` (`captcha.go`, `session.go`)
- Bouncer — subsystem — `pkg/bouncer/bouncer.go` (Language on `core_plugin_middleware`)
- Failure action — pattern — `core_plugin_lapi_failure-action` / `core_plugin_appsec_failure-action`
- Captcha gate cookie — subsystem — `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`
- Captcha request routing — subsystem — `knowledge/devdocs/core_plugin_middleware_captcha-routing.md`
- Captcha siteverify — subsystem — `knowledge/devdocs/core_plugin_middleware_captcha-siteverify.md`
- Reclaim context lease — pattern — `knowledge/devdocs/std_go_reclaim.md`
- Nested component logger — pattern — `knowledge/devdocs/std_go_logger_nested.md`
- Mock LAPI e2e — subsystem — `knowledge/devdocs/build_e2e_mock.md`
- Real-stack e2e — subsystem — `knowledge/devdocs/build_e2e_real.md`

## Findings
- [x] language-gap  Captcha Client — `core_plugin_middleware` has LAPI Client and AppSec Client, no Captcha Client term
- [x] language-gap  CaptchaEnabled — `core_plugin_middleware_config-validation` has AppsecEnabled, no CaptchaEnabled term
- [x] stale-usage  Plugin middleware New — `core_plugin_middleware` Key files omit `pkg/captcha`; Gotcha omits captcha ownership key and `ReceiveCaptcha`
- [x] stale-usage  Instance slots — `core_plugin_middleware_instance-slots` Overview names only LAPI/AppSec Open keys
- [x] stale-usage  Config validation — `core_plugin_middleware_config-validation` misses failure-action instance-name gate and captcha E2 (leftover name only)
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` still sequences a local Valid client; header is no longer on Client
- [x] stale-usage  Reclaim context lease — `std_go_reclaim` How-to names only LAPI and AppSec create
- [x] stale-usage  Nested component logger — `std_go_logger_nested` still says three constructors
