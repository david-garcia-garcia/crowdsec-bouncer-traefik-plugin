# Issues

- [ ] take small  empty `TestNew` / `Test_handleStreamCache` / `Test_crowdsecQuery` tables in `bouncer_test.go`
  Why: this run’s coverage bar replaces those TODOs with Connection/Bouncer tests. We created the requirement.

- [ ] note large  `pkg/cache` process-wide `ttl_map` (`cache.go` var `cache`)
  Why: Connection will hold `*cache.Client` but memory mode still shares one map. Fine for one-process Connection. Risk if a later change keys connections. Not taken: redis + existing tests.

- [ ] note large  `pkg/logger` never closes `OpenFile`; Windows `TestBouncerFileLogging*` TempDir cleanup FAIL
  Why: each `New` can leak a log FD. Out of scope unless logger moves onto Connection. Workaround: leave tests as on master; do not block the split.
