# Specs
change: ipv4-mapped-cidr-radix-panic

## FindSpecHost
- delta: ipv4-mapped-cidr-insert
  fold: core_plugin_ip_radix-lookup
  confidence: high
  candidates: core_plugin_ip_radix-lookup, core_plugin_middleware_config-validation, core_plugin_decisions_scopes

- modified core_plugin_ip_radix-lookup

## Archive FindSpecHost
- { deltaId: core_plugin_ip_radix-lookup, fold, spec-id: core_plugin_ip_radix-lookup, confidence: high, candidates: [core_plugin_ip_radix-lookup, core_plugin_middleware_config-validation, core_plugin_decisions_scopes] }
