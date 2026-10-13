# Specs
change: origin-scheme
- added core_plugin_clientrequest_inbound-request
- added core_plugin_middleware_captcha-gate
- added core_plugin_appsec_client

archive FindSpecHost:
- { deltaId: core_plugin_clientrequest_inbound-request, new, spec-id: core_plugin_clientrequest_inbound-request, confidence: high, candidates: [core_plugin_clientrequest_inbound-request, core_plugin_middleware_bouncer, core_plugin_ip_radix-lookup] }
- { deltaId: core_plugin_middleware_captcha-gate, fold, spec-id: core_plugin_middleware_captcha-gate, confidence: high, candidates: [core_plugin_middleware_captcha-gate, core_plugin_middleware_captcha-routing, core_plugin_middleware_captcha-siteverify] }
- { deltaId: core_plugin_appsec_client, fold, spec-id: core_plugin_appsec_client, confidence: high, candidates: [core_plugin_appsec_client, core_plugin_appsec_bot-detection, core_plugin_appsec_failure-action] }
