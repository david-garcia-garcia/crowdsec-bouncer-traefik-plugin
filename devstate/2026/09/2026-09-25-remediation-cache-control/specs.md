# Specs
change: remediation-cache-control
- fold core_plugin_middleware_captcha-widget — challenge HTML Cache-Control SHALL
- fold core_plugin_middleware_bouncer — ban page Cache-Control SHALL
archive:
  - { deltaId: core_plugin_middleware_captcha-widget, fold, spec-id: core_plugin_middleware_captcha-widget, confidence: high, candidates: [core_plugin_middleware_captcha-widget, core_plugin_middleware_captcha-routing, core_plugin_middleware_bouncer] }
  - { deltaId: core_plugin_middleware_bouncer, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer, core_plugin_appsec_bot-detection] }
