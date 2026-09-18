# Specs
change: captcha-custom-validate-body
- folded core_plugin_middleware_captcha-siteverify
- folded core_plugin_middleware_config-validation

```
verdicts:
  - { deltaId: siteverify-request-encoding, fold, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-routing, core_plugin_middleware_config-validation] }
  - { deltaId: validate-body-params, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation] }
```

Archive FindSpecHost (2026-09-18; delta folder ids on disk; Task unavailable to nested runner — same Search+Verdict on this thread):

```
verdicts:
  - { deltaId: core_plugin_middleware_captcha-siteverify, fold, spec-id: core_plugin_middleware_captcha-siteverify, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify, core_plugin_middleware_captcha-routing, core_plugin_middleware_captcha-gate, core_plugin_middleware_config-validation] }
  - { deltaId: core_plugin_middleware_config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation] }
```
