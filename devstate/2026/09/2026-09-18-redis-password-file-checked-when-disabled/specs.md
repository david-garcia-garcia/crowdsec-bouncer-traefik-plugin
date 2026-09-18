# Specs
change: redis-password-only-when-enabled
- modified core_plugin_middleware_config-validation

verdicts:
  - { deltaId: redis-password-file-gate, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_cache_redis_utilities-client, core_plugin_middleware_bouncer, core_plugin_lapi_reclaim-key] }
  - { deltaId: core_plugin_middleware_config-validation, fold|new: fold, spec-id: core_plugin_middleware_config-validation, confidence: high, candidates: [core_plugin_middleware_config-validation, core_cache_redis_utilities-client, core_plugin_middleware_bouncer, core_plugin_lapi_reclaim-key] }

archive FindSpecHost: in-process (Task spawn unavailable)
