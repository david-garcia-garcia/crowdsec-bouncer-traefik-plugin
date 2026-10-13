# Specs
change: crowdsec-connection-bouncer-split

FindSpecHost:

```
verdicts:
  - { deltaId: plugin-new-reclaim-bouncer, fold|new: new, spec-id: core_plugin_middleware_instance-reclaim, confidence: high, candidates: [] }
  - { deltaId: isolated-cache-store, fold|new: new, spec-id: core_cache_client_isolated-store, confidence: high, candidates: [core_cache_redis_in-tree-client] }
  - { deltaId: reclaim-table-copy, fold|new: new, spec-id: std_go_reclaim_context-lease, confidence: high, candidates: [] }
  - { deltaId: mock-e2e-two-configs, fold|new: new, spec-id: build_e2e_mock_dual-bouncer, confidence: high, candidates: [build_e2e_mock_redis-resp] }
```

- added core_plugin_middleware_instance-reclaim
- added core_cache_client_isolated-store
- added std_go_reclaim_context-lease
- added build_e2e_mock_dual-bouncer

core_cache_redis_in-tree-client is the Redis *client* package, not store isolation — not folded.
build_e2e_mock_redis-resp is RESP mock Redis, not dual bouncers — not folded.
