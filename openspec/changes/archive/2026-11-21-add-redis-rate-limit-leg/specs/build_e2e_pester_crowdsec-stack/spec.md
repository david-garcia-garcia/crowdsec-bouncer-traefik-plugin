## ADDED Requirements

### Requirement: Real stack covers the Redis rate limit
The real-stack Pester suite SHALL run the rate-limit leg inside Traefik's plugin loader against the stack's Dragonfly service, configured through the file provider (the bucket list is a list of objects with nested lists, which Docker labels do not decode). It SHALL prove: a `deny` bucket answers `rateLimitStatusCode` with `Retry-After` and remediation header `ban:ratelimit:<bucket>` after `requests` hits; a different client address is not limited by that counter; a `bypassRateLimit` action rule lets the over-limit client through; a `log` bucket never denies; an unreachable Redis with `rateLimitFailureAction: passthrough` lets the request through and with `ban` answers `ban:ratelimit-failure`; and a rate-limit deny reaches `cscli metrics` as a drop with origin `plugin:ratelimit:<bucket>`. Each case SHALL use a client address no other case uses, so counters left in Dragonfly by an earlier run or case cannot change the result. The file SHALL be listed in one CI Pester domain.

#### Scenario: Deny after the limit on real Traefik
- **WHEN** a client sends `requests + 1` requests to a route whose `deny` bucket allows `requests` per window
- **THEN** the last response is 429 with `Retry-After`
- **AND** the remediation header is `ban:ratelimit:<bucket>`

#### Scenario: Redis down with passthrough
- **WHEN** the middleware points `rateLimitRedisHost` at a port where nothing listens and `rateLimitFailureAction` is `passthrough`
- **THEN** requests reach the backend

#### Scenario: Deny is a drop in cscli
- **WHEN** a rate-limit deny happens on a router with a LAPI client and a short metrics interval
- **THEN** `cscli metrics` for that bouncer shows a dropped count under origin `plugin:ratelimit:<bucket>`
