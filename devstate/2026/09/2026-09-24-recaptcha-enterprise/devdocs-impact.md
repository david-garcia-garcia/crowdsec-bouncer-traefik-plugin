# Devdocs impact
change: recaptcha-enterprise

## Units
- Captcha Client — subsystem — `pkg/captcha/captcha.go` / `core_plugin_middleware.md`
- Siteverify — subsystem — `pkg/captcha/siteverify.go` / `core_plugin_middleware_captcha-siteverify`
- Assessment — subsystem — `pkg/captcha/assessments.go` / spec `core_plugin_middleware_captcha-assessments`
- Widget — subsystem — `pkg/captcha/widget.go` / spec `core_plugin_middleware_captcha-widget`
- Config validation — subsystem — `pkg/configuration/configuration.go` / `core_plugin_middleware_config-validation`
- Captcha enterprise config — subsystem — spec `core_plugin_middleware_captcha-enterprise-config`
- Instance slots — subsystem — `pkg/captcha/session.go` / `core_plugin_middleware_instance-slots`
- Captcha request routing — subsystem — `pkg/bouncer/bouncer.go` / `core_plugin_middleware_captcha-routing`
- Captcha gate cookie — subsystem — `pkg/captcha/gate.go` / `core_plugin_middleware_captcha-gate`
- GetRemoteIP — subsystem — `pkg/ip/checker.go` / `core_plugin_ip`

## Findings
- [x] missing-packet  Assessment — `core_plugin_middleware_captcha-assessments`
- [x] missing-packet  Widget — `core_plugin_middleware_captcha-widget`
- [x] missing-packet  Captcha enterprise config — `core_plugin_middleware_captcha-enterprise-config`
- [x] language-gap  Captcha Client — `core_plugin_middleware`
