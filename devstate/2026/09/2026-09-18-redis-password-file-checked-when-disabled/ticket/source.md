# Redis password file checked when Redis is disabled

ValidateParams always resolves LapiRedisPassword (`pkg/configuration/configuration.go:326-328`) with no LapiRedisEnabled guard. lapiRedisEnabled:false plus a stale/missing lapiRedisPasswordFile fails startup. Proven FAIL: TestHunt_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled. Fix: resolve/require LapiRedisPassword / LapiRedisPasswordFile only when lapiRedisEnabled is true. Include a regression test. Bound the ask to this defect only.
