## ADDED Requirements

### Requirement: Real stack includes a Dragonfly Redis-protocol cache
`tests/e2e/real/docker-compose.test.yml` SHALL start Dragonfly (`docker.dragonflydb.io/dragonflydb/dragonfly:v1.40.2`, port 6379, `ulimits.memlock: -1`) in addition to Traefik and Crowdsec. At least one Pester route SHALL set `redisCacheEnabled` and `redisCacheHost` to that Dragonfly service. Pester SHALL prove live-mode cache hit/miss against Dragonfly. Client identity SHALL remain only `X-Forwarded-For` (Traefik forwarded headers plus plugin `forwardedHeadersTrustedIps`).

#### Scenario: Live-mode Redis cache allow then ban after TTL
- **WHEN** the Dragonfly-backed live-mode route is used, a request is allowed, then a ban is added for that `X-Forwarded-For`
- **THEN** the next request is still allowed until `defaultDecisionSeconds`, after which the same IP is forbidden and a different IP still passes

#### Scenario: Cached ban survives Traefik restart
- **WHEN** a ban is cached in Dragonfly for the test IP and the Traefik container is restarted
- **THEN** a request with that `X-Forwarded-For` is still forbidden without waiting for a new LAPI miss (in-memory-only cache would miss)
