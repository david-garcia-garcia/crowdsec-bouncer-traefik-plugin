# Issues

- [ ] take small  empty `TestNew` / `Test_handleStreamCache` / `Test_crowdsecQuery` tables in `bouncer_test.go`
  Why: this run’s coverage bar replaces those TODOs with Connection/Bouncer tests. We created the requirement.

- [ ] take small  `pkg/cache` process-wide `ttl_map` → per-Connection isolated store (own map; Redis key prefix = connection identity)
  Why: human: each Connection gets its own cache space so tests and two LAPIs cannot collide. Captcha uses that Client.

- [ ] note large  `pkg/logger` never closes `OpenFile`; Windows `TestBouncerFileLogging*` TempDir cleanup FAIL
  Why: each `New` can leak a log FD. Out of scope unless logger moves onto Connection. Workaround: leave tests as on master; do not block the split.
