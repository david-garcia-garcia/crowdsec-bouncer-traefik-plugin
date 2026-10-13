# Specs
change: remediation-header-reasons

Live catalog: live promises (structured `bouncerRemediationHeadersCustomName` values). FindSpecHost ran before each folder write.

verdicts:
  - { deltaId: core_plugin_middleware_bouncer, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_middleware_forced-decision, core_plugin_lapi_usage-metrics, core_plugin_appsec_client] }
  - { deltaId: core_plugin_middleware_captcha-widget, fold, spec-id: core_plugin_middleware_captcha-widget, confidence: high, candidates: [core_plugin_middleware_captcha-widget, core_plugin_middleware_captcha-routing, core_plugin_middleware_captcha-gate] }
  - { deltaId: core_plugin_middleware_captcha-routing, fold, spec-id: core_plugin_middleware_captcha-routing, confidence: high, candidates: [core_plugin_middleware_captcha-routing, core_plugin_middleware_captcha-widget] }
  - { deltaId: core_plugin_appsec_bot-detection, fold, spec-id: core_plugin_appsec_bot-detection, confidence: high, candidates: [core_plugin_appsec_bot-detection, core_plugin_appsec_client, core_plugin_middleware_bouncer] }

- fold core_plugin_middleware_bouncer — vocabulary table + emit rules; keep error:client-disconnected exact
- fold core_plugin_middleware_captcha-widget — solved-captcha → captcha:solved; challenge value is caller-supplied
- fold core_plugin_middleware_captcha-routing — solved-captcha → captcha:solved
- fold core_plugin_appsec_bot-detection — raw AppSec action → structured header
