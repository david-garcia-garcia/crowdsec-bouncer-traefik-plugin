# Specs
change: parse-client-ip-once

verdicts:
  - { deltaId: getremoteip-netip-containsip, fold, spec-id: core_plugin_ip_radix-lookup, confidence: high, candidates: [core_plugin_ip_radix-lookup] }
  - { deltaId: range-remediation-netip, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes] }
  - { deltaId: ip-type-from-parsed, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics] }

- modified core_plugin_ip_radix-lookup
- modified core_plugin_decisions_scopes
- modified core_plugin_lapi_usage-metrics

archive FindSpecHost:
  - { deltaId: core_plugin_ip_radix-lookup, fold, spec-id: core_plugin_ip_radix-lookup, confidence: high }
  - { deltaId: core_plugin_decisions_scopes, fold, spec-id: core_plugin_decisions_scopes, confidence: high }
  - { deltaId: core_plugin_lapi_usage-metrics, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high }

