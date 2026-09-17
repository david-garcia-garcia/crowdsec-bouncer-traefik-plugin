## 1. Configuration

- [ ] 1.1 Add `RedisCacheInstanceId` / map key `redisCacheInstanceId` to Configuration
- [ ] 1.2 Validate when `redisCacheEnabled`: trim, max 128 runes, charset `[A-Za-z0-9._-]+` when non-empty

## 2. Instance identity and CachePrefix

- [ ] 2.1 Implement effective instance id resolution (config → hostname → `unknown-instance` + Warn)
- [ ] 2.2 Extend `CachePrefix` to `{hexBase}:{instanceId}` for stream/alone and live/none when Redis enabled
- [ ] 2.3 Wire config into LAPI Client construction so prefix is stable for Client lifetime

## 3. Tests

- [ ] 3.1 Unit tests for validation rules and prefix formatting
- [ ] 3.2 Tests that two instance identities do not share stream lease or remediation keys on same Redis host
- [ ] 3.3 Regression: same process same session still shares one prefix (warn-and-wire)

## 4. Devdocs

- [ ] 4.1 Update `knowledge/devdocs/core_cache_redis.md` for instance prefix and LAPI cursor vs Redis roles

## 5. Verify

- [ ] 5.1 `go test ./pkg/lapi/ ./pkg/cache/ ./pkg/configuration/`
