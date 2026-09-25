# Devdocs impact
change: remediation-cache-control

## Units
- Widget — subsystem — `pkg/captcha/captcha.go` `ServeHTTP`, spec `core_plugin_middleware_captcha-widget`
- Ban page — subsystem — `pkg/bouncer/bouncer.go` `handleBanServeHTTP`, spec `core_plugin_middleware_bouncer`

## Findings
- [x] stale-usage  Widget — `core_plugin_middleware_captcha-widget` How-to rendered challenge 200 with no `Cache-Control`; Pass 302 omitted the do-not-set rule
- [x] missing-packet  Ban page — no packet; only a New-time "put ban templates on Bouncer" bullet on `core_plugin_middleware`
