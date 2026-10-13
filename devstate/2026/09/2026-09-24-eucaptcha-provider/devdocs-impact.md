# Devdocs impact
change: eucaptcha-provider

## Units
- Eucaptcha verify — subsystem — `pkg/captcha/eucaptcha.go` / spec `core_plugin_middleware_captcha-eucaptcha-verify`
- Widget — subsystem — `pkg/captcha/captcha.go` New pairing / spec `core_plugin_middleware_captcha-widget`
- Captcha enterprise config — subsystem — `pkg/configuration/configuration.go` allowlist / spec `core_plugin_middleware_captcha-enterprise-config`
- Config validation — subsystem — `validateCaptchaCredentials` secret-required / spec `core_plugin_middleware_config-validation`
- Captcha siteverify — subsystem — `pkg/captcha/siteverify.go` Pass arity
- Assessment — subsystem — `pkg/captcha/assessments.go` Pass arity
- Captcha gate cookie — subsystem — `pkg/captcha/gate.go` mint on Validate Pass
- Trusted-IP lookup — subsystem — GetRemoteIP / `clientRequest.remoteIP` (`core_plugin_ip`)

## Findings
- [x] stale-usage  Captcha gate cookie — `core_plugin_middleware_captcha-gate` Language said mint is after siteverify; apply mints on Validate Pass (eucaptcha included)
- [x] stale-usage  Captcha enterprise config — `core_plugin_middleware_captcha-enterprise-config` leftover-knobs How-to and Enterprise knobs Avoid omitted `eucaptcha`
