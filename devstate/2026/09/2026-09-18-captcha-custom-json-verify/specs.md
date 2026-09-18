# Specs
change: captcha-custom-validate-body
- folded core_plugin_middleware_captcha-siteverify
- folded core_plugin_middleware_config-validation

```
verdicts:
  - { deltaId: siteverify-request-encoding, fold, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-routing, core_plugin_middleware_config-validation] }
  - { deltaId: validate-body-params, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation] }
```
