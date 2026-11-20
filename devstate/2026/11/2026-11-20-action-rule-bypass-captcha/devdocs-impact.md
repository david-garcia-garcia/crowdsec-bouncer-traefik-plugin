# Devdocs impact
change: action-rule-bypass-captcha

## Units
- Action rules — subsystem — `pkg/httprule/action.go`, `pkg/bouncer/bouncer_serve_captcha.go` (`bypassesCaptcha`)
- HTTP request rules — subsystem — `pkg/httprule` (`ActionSet.Fold`, `ActionMatch.BypassCaptchaName`)
- OriginBasedDecisionRemap — subsystem — `pkg/bouncer/origin_based_decision_remap.go` (`appliedLAPIRemediation`)
- Captcha routing — subsystem — `pkg/bouncer/bouncer_serve_captcha.go` (`serveAppsecCaptchaGate`, `handleCaptchaKindServeHTTP`)
- AppSec verdicts — subsystem — `pkg/bouncer/bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`

## Findings
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules` did not name the `bypassCaptcha` token, the predicate, or its gotchas (written in implement)
- [x] stale-usage  HTTP request rules — `core_plugin_httprule` described `Fold` and `SingleReadingPath` without the token (written in implement)
- [x] stale-usage  OriginBasedDecisionRemap — `core_plugin_lapi_origin-based-decision-remap` showed `appliedLAPIRemediation` without the match and without the kept ban
- [x] stale-usage  Captcha routing — `core_plugin_middleware_captcha-routing` listed the cases that do not write without the bypassed captcha
- [x] stale-usage  AppSec verdicts — `core_plugin_appsec` said an AppSec `captcha` always serves the gate
