# Specs
change: split-ip-checker-network
- modified core_plugin_ip_radix-lookup (fold)

FindSpecHost:
  - { deltaId: getremoteip-forwarded-walk, fold, spec-id: core_plugin_ip_radix-lookup, confidence: high, candidates: [core_plugin_ip_radix-lookup, core_plugin_middleware_instance-reclaim, core_plugin_decisions_scopes] }
