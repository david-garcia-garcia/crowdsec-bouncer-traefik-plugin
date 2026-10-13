# Devdocs impact
change: remediation-header-reasons

## Units
- Bouncer remediation header — subsystem — `pkg/bouncer/remediation_header.go`
- Ban page — subsystem — `pkg/bouncer/bouncer.go` `handleBanServeHTTP`
- Captcha request routing — subsystem — `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP`
- Widget — subsystem — `pkg/captcha/captcha.go` `ServeHTTP`
- AppSec challenge — subsystem — `pkg/bouncer/bouncer.go` `handleAppsecResponseServeHTTP`
- Forced decision header — subsystem — `pkg/bouncer/bouncer.go` `forcedDecisionKind`

## Findings
- [x] language-gap  Bouncer remediation header — `core_plugin_middleware` has How-to, no Language term
- [x] stale-usage  Ban page — `core_plugin_middleware_ban-page` still says writers Set the same literal
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` still says `solved-captcha` and ServeHTTP without the formatted challenge value
- [x] stale-usage  Widget — `core_plugin_middleware_captcha-widget` still says `solved-captcha`
- [x] stale-usage  AppSec challenge — `core_plugin_appsec` still omits structured relay / ban header values
- [x] stale-usage  Forced decision header — `core_plugin_middleware_forced-decision` does not name outgoing `ban:decision-header` / `captcha:decision-header`

Verdict: in progress
