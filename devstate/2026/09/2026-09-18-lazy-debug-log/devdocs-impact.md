# Devdocs impact
change: lazy-debug-hot-path

## Units
- Request-path Debug attributes — pattern — `pkg/bouncer/bouncer.go` ServeHTTP Debug, `pkg/cache/cache.go` Get/GetMany/Set/Delete
- DecisionStore cache — subsystem — `knowledge/devdocs/core_cache_client.md`
- Bouncer / middleware New — subsystem — `knowledge/devdocs/core_plugin_middleware.md`
- Trusted-IP lookup — subsystem — `knowledge/devdocs/core_plugin_ip.md`
- Test log sink — pattern — `knowledge/devdocs/std_go_test_log-sink.md`

## Findings
- [x] missing-packet  Request-path Debug attributes — no packet; produced `std_go_logger_debug-attrs.md`
- [x] stale-usage  Test log sink — Key files listed only `pkg/lapi`; added cache and bouncer sink paths
