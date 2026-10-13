# Redis password file checked when Redis is disabled

ValidateParams always resolves RedisCachePassword (`pkg/configuration/configuration.go:326-328`) with no RedisCacheEnabled guard. redisCacheEnabled:false plus a stale/missing redisCachePasswordFile fails startup. Proven FAIL: TestHunt_ValidateParams_skipsRedisPasswordFileWhenRedisDisabled. Fix: resolve/require RedisCachePassword / RedisCachePasswordFile only when redisCacheEnabled is true. Include a regression test. Bound the ask to this defect only.
