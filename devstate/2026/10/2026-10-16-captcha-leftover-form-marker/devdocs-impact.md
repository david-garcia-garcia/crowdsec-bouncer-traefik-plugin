# Devdocs impact
change: captcha-challenge-form-marker

## Units
- Captcha request routing — subsystem — `pkg/captcha/captcha.go` `IsCaptchaFormPost`, `pkg/bouncer/bouncer.go` `handleCaptchaKindServeHTTP`, spec `core_plugin_middleware_captcha-routing`
- Widget — subsystem — shipped challenge HTML plus `pkg/captcha` widget pairing, spec `core_plugin_middleware_captcha-widget`

## Findings
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` First-verify reader and How-to still name `captchaResponseFromRequest`; Key files omit `pkg/captcha/form.go`; leftover detection still reads as if `TokenField` must be set
- [x] stale-usage  Widget — `core_plugin_middleware_captcha-widget` How-to and Key files do not name the six shipped challenge pages that emit leftover-form marker
