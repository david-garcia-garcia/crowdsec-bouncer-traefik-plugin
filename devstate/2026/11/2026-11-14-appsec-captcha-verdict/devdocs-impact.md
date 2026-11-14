# Devdocs impact
change: appsec-captcha-verdict

## Units
- AppSec verdict handling — subsystem — `pkg/bouncer` `applyAppsecServeHTTP` / `serveAppSec`; spec `core_plugin_appsec_bot-detection`
- Captcha request routing — subsystem — `pkg/bouncer` `handleCaptchaKindServeHTTP` (new AppSec entry `serveAppsecCaptchaGate`)
- Ban page header reasons — pattern — `handleBanServeHTTP` closed reasons (`appsec-action-empty`)
- Mock e2e AppSec stand-in — pattern — `tests/e2e/mock/mocklapi`, scenario `appsec-captcha`

## Findings
- [x] language-gap  AppSec captcha verdict — `core_plugin_appsec` had no term; "AppSec captcha verdict" added (implement)
- [x] stale-usage  AppSec verdict switch and marker POST — `core_plugin_appsec` How-to rewritten for captcha gate, bodyless unknown action, `isCaptchaFormAnswer` (implement, codereview)
- [x] stale-usage  Captcha routing caller reasons — `core_plugin_middleware_captcha-routing` Overview, How-to and Gotcha updated; Language _Avoid_ no longer excludes AppSec captcha (implement)
- [x] stale-usage  Closed ban reasons — `core_plugin_middleware_ban-page` "do not infer" list gains `appsec-action-empty`
- [x] stale-usage  AppSec stand-in verdict probes — `build_e2e_mock` How-to names the URI probes and lists scenario `appsec-captcha`
