# Devdocs impact
change: config-domain-prefixes

## Units
- Config validation — subsystem — `pkg/configuration/configuration.go` + `core_plugin_middleware_config-validation`
- Middleware New — subsystem — `plugin.go` + `pkg/bouncer` + `core_plugin_middleware`
- LAPI connection — subsystem — `pkg/lapi/client.go`, `pkg/lapi/client_http.go`
- LAPI reclaim key — subsystem — `pkg/lapi/identity.go`, `pkg/lapi/session.go`
- AppSec challenge — subsystem — `pkg/appsec`
- LAPI opener stream scopes — subsystem — `core_plugin_lapi_scope-union`
- DecisionStore — subsystem — `pkg/decisionstore` + `core_plugin_decisionstore`
- Decision scopes — subsystem — `pkg/decisionscope` + `core_plugin_decisionscope`
- Forced decision header — subsystem — `core_plugin_middleware_forced-decision`
- OriginBasedDecisionRemap — subsystem — `core_plugin_lapi_origin-based-decision-remap`
- Trusted-IP lookup — subsystem — `core_plugin_ip`
- Captcha gate cookie — subsystem — `core_plugin_middleware_captcha-gate`
- Captcha siteverify — subsystem — `core_plugin_middleware_captcha-siteverify`
- Captcha request routing — subsystem — `core_plugin_middleware_captcha-routing`
- Real-stack e2e — subsystem — `tests/e2e/real` + `build_e2e_pester_crowdsec-stack`
- Mock LAPI e2e — subsystem — `tests/e2e/mock` + `build_e2e_mock`
- LAPI usage-metrics — subsystem — `core_plugin_lapi_usage-metrics` (forced-header origin line)

## Findings
- [x] language-gap  Config validation — `core_plugin_middleware_config-validation` still has `EffectiveHTTPTimeoutSeconds` and `CrowdsecAppsecEnabled`; no Config domain prefix
- [x] stale-usage  Middleware New — `core_plugin_middleware` How-to still inherit-timeout, `streamStartupBlock`, and `crowdsec*` axes
- [x] stale-usage  LAPI connection — `core_plugin_lapi_connection` still calls `EffectiveHTTPTimeoutSeconds` and parks `StreamStartupBlock` on the Client
- [x] language-gap  LAPI reclaim key — `core_plugin_lapi_reclaim-key` Ownership key / SessionHex still name `crowdsecLapiStreamScopes`, `redisCacheEnabled`, `streamStartupBlock`
- [x] stale-usage  AppSec challenge — `core_plugin_appsec` How-to still inherit-timeout and `crowdsecAppsec*`
- [x] language-gap  LAPI opener stream scopes — `core_plugin_lapi_scope-union` still names `crowdsecLapiStreamScopes` / `decisionScopeHeaders`
- [x] stale-usage  DecisionStore — `core_plugin_decisionstore` How-to still names `crowdsecLapiStreamScopes` / `decisionScopeHeaders`
- [x] language-gap  Decision scopes — `core_plugin_decisionscope` Language still names `decisionScopeHeaders`
- [x] language-gap  Forced decision header — `core_plugin_middleware_forced-decision` still names `crowdsecDecisionHeader`
- [x] language-gap  OriginBasedDecisionRemap — `core_plugin_lapi_origin-based-decision-remap` still names `originBasedDecisionRemap`
- [x] language-gap  Trusted-IP lookup — `core_plugin_ip` still names `ForwardedHeadersTrustedIPs` / `ClientTrustedIPs`
- [x] language-gap  Captcha gate cookie — `core_plugin_middleware_captcha-gate` still names `captchaGateSecret` / `CaptchaSecretKey`
- [x] stale-usage  Captcha siteverify — `core_plugin_middleware_captcha-siteverify` How-to still names `CaptchaCustomValidateBody`
- [x] stale-usage  Captcha request routing — `core_plugin_middleware_captcha-routing` still names `captchaCustomChallengeUrl`
- [x] stale-usage  Real-stack e2e — `build_e2e_real` still names old compose keys and `httpTimeoutSeconds`
- [x] stale-usage  Mock LAPI e2e — `build_e2e_mock` still names `captchaFilePath` / `captchaProvider`
- [x] stale-usage  LAPI usage-metrics — `core_plugin_lapi_usage-metrics` still names `crowdsecDecisionHeader`
