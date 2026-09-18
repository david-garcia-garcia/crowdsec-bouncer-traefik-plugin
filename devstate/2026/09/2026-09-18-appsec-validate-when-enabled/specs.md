# Specs
change: appsec-validate-when-enabled

- folded `core_plugin_middleware_config-validation`
  verdict: fold
  confidence: high
  candidates: `core_plugin_middleware_config-validation`, `core_plugin_appsec_client`, `core_plugin_middleware_bouncer`

- archive FindSpecHost `core_plugin_middleware_config-validation`
  verdict: fold
  spec-id: `core_plugin_middleware_config-validation`
  confidence: high
  candidates: `core_plugin_middleware_config-validation`, `core_plugin_appsec_client`, `core_plugin_middleware_bouncer`
  note: Task unavailable in archive subagent; FindSpecHost ran on this thread
