# Devdocs impact
change: crowdsec-connection-bouncer-split

## Units
- Middleware New — subsystem — `plugin.go` / spec `core_plugin_middleware_instance-reclaim`
- Reclaim table — pattern — `pkg/reclaim` / spec `std_go_reclaim_context-lease`
- Isolated cache Client — subsystem — `pkg/cache` / spec `core_cache_client_isolated-store`
- Redis cache client — subsystem — `pkg/cache` redis path / `core_cache_redis.md`
- Mock e2e — subsystem — `tests/e2e/mock/` / spec `build_e2e_mock_dual-bouncer`

## Findings
- [x] missing-packet  Middleware New — no packet; Traefik `New` now reclaims CrowdsecConnection
- [x] missing-packet  Reclaim table — no `std/go` usage packet
- [x] missing-packet  Isolated cache Client — neighbor Redis packet does not own isolation
- [x] stale-usage  Redis cache client — `Client.New` takes `keyPrefix`; Redis keys are no longer bare client IP
- [x] missing-packet  Mock e2e — real-stack packet is not the mock suite; dual-bouncer lives under `tests/e2e/mock/`
