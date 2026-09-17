# Devdocs impact
change: honor-range-and-header-decisions

## Units
- Decision scopes — subsystem — `pkg/decisionscope/`
- Isolated cache Client — subsystem — `pkg/cache/cache.go` GetMany keys
- Redis cache client — subsystem — `pkg/simpleredis` MGET on request lookup
- Plugin middleware New — subsystem — `pkg/bouncer` ServeHTTP lookup
- Real-stack e2e — pattern — `tests/e2e/real/decision_scopes.Tests.ps1`
- Mock LAPI e2e — pattern — `tests/e2e/mock/scenarios/scope-headers/`

## Findings
- [x] missing-packet  Decision scopes — no packet; `pkg/decisionscope` is a new owner
- [x] stale-usage  Redis cache client — `core_cache_redis.md` said one GET per request / IP-only keys
- [x] stale-usage  Isolated cache Client — logical keys are no longer IP-only
- [x] stale-usage  Real-stack e2e — Country via geoblock and file provider were missing
- [x] stale-usage  Mock LAPI e2e — `scope-headers` scenario was missing
- [x] stale-usage  Plugin middleware New — ServeHTTP now calls `pkg/decisionscope` (pointer only)
