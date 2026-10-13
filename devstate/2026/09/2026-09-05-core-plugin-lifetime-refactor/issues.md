# Issues

- [x] take small  empty `TestNew` / `Test_handleStreamCache` / `Test_crowdsecQuery` tables in `bouncer_test.go`
  Why: this run’s coverage bar replaces those TODOs with Connection/Bouncer tests. We created the requirement.
  Implement: replaced with plugin_test.go two-LAPI / reclaim / ServeHTTP matrix (`f116ac8`).

- [x] take small  `pkg/cache` process-wide `ttl_map` → per-Connection isolated store (own map; Redis key prefix = connection identity)
  Why: human: each Connection gets its own cache space so two configs cannot collide.
  Implement: per-Client `ttl_map`; Redis `prefixed(identityHex, key)` (`f116ac8`).

- [x] take small  mock e2e scenario: one Traefik, two bouncer middlewares, two LAPIs
  Why: human: two configs in the same Traefik instance is the point. Existing harness under `tests/e2e/mock/scenarios/`.
  Implement: `tests/e2e/mock/scenarios/dual-bouncer/` plus `--lapi-only` (`f116ac8`).

- [ ] note large  `pkg/logger` never closes `OpenFile`; Windows `TestBouncerFileLogging*` TempDir cleanup FAIL
  Why: each `New` can leak a log FD. Out of scope unless logger moves onto Connection. Workaround: leave tests as on master; do not block the split.
