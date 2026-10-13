# Specs
change: captcha-verify-template-ux

verdicts:
  - { deltaId: siteverify-remoteip-and-retryable-errors, fold, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-gate, core_plugin_middleware_captcha-routing, core_plugin_ip] }
  - { deltaId: provider-set-loadable-captcha-template, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation] }
  - { deltaId: core_plugin_middleware_captcha-siteverify, fold, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-gate, core_plugin_middleware_captcha-routing, core_plugin_middleware_bouncer, core_plugin_ip_radix-lookup] }
  - { deltaId: core_plugin_middleware_config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-gate] }

- modified core_plugin_middleware_captcha-siteverify
- modified core_plugin_middleware_config-validation
