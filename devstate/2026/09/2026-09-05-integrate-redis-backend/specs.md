# Specs
change: in-tree-simpleredis-dragonfly-e2e

verdicts:
  - { deltaId: in-tree-client, new, spec-id: core_cache_redis_in-tree-client, confidence: high, candidates: [] }
  - { deltaId: dragonfly-e2e, fold, spec-id: build_e2e_pester_crowdsec-stack, confidence: high, candidates: [build_e2e_pester_crowdsec-stack] }
  - { deltaId: mock-redis-resp, new, spec-id: build_e2e_mock_redis-resp, confidence: high, candidates: [] }

- added core_cache_redis_in-tree-client
- added build_e2e_mock_redis-resp
- modified build_e2e_pester_crowdsec-stack
