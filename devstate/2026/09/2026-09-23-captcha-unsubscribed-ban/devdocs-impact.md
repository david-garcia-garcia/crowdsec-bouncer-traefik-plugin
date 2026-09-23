# Devdocs impact
change: unsubscribed-captcha-ban-warn

## Units
- Bouncer — subsystem — `pkg/bouncer/bouncer.go`, spec `core_plugin_middleware_bouncer`
- Captcha request routing — subsystem — `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`
- Subscribe gate — pattern — `plugin.go` `subscribeCaptcha`
- Forced decision header — subsystem — `pkg/bouncer/bouncer.go` forced `c`

## Findings
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` How-to and Overview omit the unsubscribed WARN-then-ban gate
- [x] language-gap  Unsubscribed captcha — `core_plugin_middleware_captcha-routing` has no Language term for `subscribeCaptcha` false
