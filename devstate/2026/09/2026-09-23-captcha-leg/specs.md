# Specs
change: captcha-leg

Live catalog: live promises (named captcha slot, bounce binding, validation gates, failure-action `captcha`, gate-secret trigger, e2e public keys). FindSpecHost ran before each folder write.

verdicts:
  - { deltaId: instance-slots, fold, spec-id: core_plugin_middleware_instance-slots, confidence: high, candidates: [core_plugin_middleware_instance-slots, std_go_reclaim_context-lease] }
  - { deltaId: bouncer-binding, fold, spec-id: core_plugin_middleware_bouncer, confidence: high, candidates: [core_plugin_middleware_bouncer] }
  - { deltaId: config-validation, fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation] }
  - { deltaId: lapi-failure-action, fold, spec-id: core_plugin_lapi_failure-action, confidence: high, candidates: [core_plugin_lapi_failure-action] }
  - { deltaId: appsec-failure-action, fold, spec-id: core_plugin_appsec_failure-action, confidence: high, candidates: [core_plugin_appsec_failure-action] }
  - { deltaId: captcha-gate, fold, spec-id: core_plugin_middleware_captcha-gate, confidence: high, candidates: [core_plugin_middleware_captcha-gate] }
  - { deltaId: e2e-pester, fold, spec-id: build_e2e_pester_crowdsec-stack, confidence: high, candidates: [build_e2e_pester_crowdsec-stack] }
  - { deltaId: captcha-routing, skip, spec-id: none, confidence: high, candidates: [core_plugin_middleware_captcha-routing] }
  - { deltaId: captcha-siteverify, skip, spec-id: none, confidence: high, candidates: [core_plugin_middleware_captcha-siteverify] }
  - { deltaId: reclaim-table, skip, spec-id: none, confidence: high, candidates: [std_go_reclaim_context-lease] }

- fold core_plugin_middleware_instance-slots
- fold core_plugin_middleware_bouncer
- fold core_plugin_middleware_config-validation
- fold core_plugin_lapi_failure-action
- fold core_plugin_appsec_failure-action
- fold core_plugin_middleware_captcha-gate
- fold build_e2e_pester_crowdsec-stack
- skip captcha-routing — routing contract unchanged
- skip captcha-siteverify — encoding contract unchanged
- skip std_go_reclaim_context-lease — reuse existing Open/SetAlias/Watch; no new table
