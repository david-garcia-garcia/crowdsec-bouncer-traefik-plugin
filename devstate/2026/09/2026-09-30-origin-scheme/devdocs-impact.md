# Devdocs impact
change: origin-scheme

## Units
- Inbound request — subsystem — `pkg/clientrequest` / spec `core_plugin_clientrequest_inbound-request`
- Captcha gate cookie — subsystem — `pkg/captcha/gate.go` / spec `core_plugin_middleware_captcha-gate`
- AppSec query — subsystem — `pkg/appsec/query.go` / spec `core_plugin_appsec_client`
- Trusted-IP lookup — subsystem — `pkg/ip` / `core_plugin_ip.md`
- Plugin middleware New — subsystem — `core_plugin_middleware.md`
- Captcha request routing — subsystem — `core_plugin_middleware_captcha-routing.md`
- Decision scopes — subsystem — `core_plugin_decisionscope.md`
- Assessment — subsystem — `core_plugin_middleware_captcha-assessments.md`
- Eucaptcha verify — subsystem — `core_plugin_middleware_captcha-eucaptcha-verify.md`
- Widget — subsystem — `core_plugin_middleware_captcha-widget.md`
- Request-path Trace — pattern — `std_go_logger_debug-attrs.md`
- Action rules — subsystem — `core_plugin_middleware_action-rules.md`
- LAPI usage-metrics — subsystem — `core_plugin_lapi_usage-metrics.md`
- OriginBasedDecisionRemap — subsystem — `core_plugin_lapi_origin-based-decision-remap.md`

## Findings
- [x] missing-packet  Inbound request — `core_plugin_clientrequest_inbound-request`
- [x] stale-usage  Captcha gate cookie — `core_plugin_middleware_captcha-gate`
- [x] stale-usage  AppSec query — `core_plugin_appsec`
- [x] stale-usage  Trusted-IP lookup — `core_plugin_ip`
- [x] stale-usage  Plugin middleware New — `core_plugin_middleware`
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing`
- [x] stale-usage  Decision scopes — `core_plugin_decisionscope`
- [x] stale-usage  Assessment — `core_plugin_middleware_captcha-assessments`
- [x] stale-usage  Eucaptcha verify — `core_plugin_middleware_captcha-eucaptcha-verify`
- [x] stale-usage  Widget — `core_plugin_middleware_captcha-widget`
- [x] stale-usage  Request-path Trace — `std_go_logger_debug-attrs`
- [x] stale-usage  Action rules — `core_plugin_middleware_action-rules`
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics`
- [x] stale-usage  OriginBasedDecisionRemap — `core_plugin_lapi_origin-based-decision-remap`
