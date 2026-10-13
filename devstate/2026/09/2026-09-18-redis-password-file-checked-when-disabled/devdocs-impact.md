# Devdocs impact
change: redis-password-only-when-enabled

## Units
- Config validation — subsystem — `pkg/configuration/configuration.go` (`ValidateParams`) / spec `core_plugin_middleware_config-validation`
- Redis cache client — subsystem — `knowledge/devdocs/core_cache_redis.md`

## Findings
- [x] missing-packet  Config validation — no packet; only a ValidateParams gotcha on `core_plugin_middleware.md`
