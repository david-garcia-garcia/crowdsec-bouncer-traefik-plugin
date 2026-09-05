# Specs
change: put-decision-scope-headers-on-identity
archived: openspec/changes/archive/2026-09-05-put-decision-scope-headers-on-identity/

verdicts:
  - { deltaId: reclaim-identity-includes-map, fold, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [core_plugin_middleware_instance-reclaim, core_plugin_lapi_failure-action, core_plugin_decisions_scopes] }
  - { deltaId: bouncer-reads-connection-map, fold, spec-id: core_plugin_decisions_scopes, confidence: high, candidates: [core_plugin_decisions_scopes, core_plugin_middleware_instance-reclaim] }

- modified core_plugin_middleware_instance-reclaim
- modified core_plugin_decisions_scopes

archive FindSpecHost: same verdicts; catalog synced then moved.
