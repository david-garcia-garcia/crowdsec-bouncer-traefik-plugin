# Specs
change: canonicalize-client-remoteip

FindSpecHost:
- { deltaId: ip-request-key-owner, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes] }
- archive { deltaId: core_plugin_decisions_scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_ip_radix-lookup, core_plugin_middleware_captcha-gate, core_plugin_middleware_bouncer, core_cache_client_decision-store] }

- modified core_plugin_decisions_scopes
