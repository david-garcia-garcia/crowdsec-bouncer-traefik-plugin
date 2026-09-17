## MODIFIED Requirements

### Requirement: Range decisions match by CIDR containment
When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. Range membership SHALL be stored on one shared cache key `range-index` as `cidr=remediation` lines on that LAPI Client’s in-memory cache. When several containing CIDRs hit, `ban` SHALL win over `captcha`. In stream and alone modes, the request path SHALL match Range from in-process membership rebuilt from that blob and MUST NOT read `range-index` on the request. live and none SHALL keep skipping `range-index` and expand Range via LAPI `?ip=`.

#### Scenario: Stream Range contains the client
- **WHEN** stream or alone mode has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden

#### Scenario: IP outside the Range still passes
- **WHEN** only that Range ban exists and the client IP is `203.0.113.10`
- **THEN** the request is allowed

#### Scenario: Empty Range membership is a miss
- **WHEN** stream mode has no Range decisions
- **THEN** Range matching does not remediate the request

## REMOVED Requirements

### Requirement: Redis replica that skipped LAPI still matches Range
**Reason**: No cross-replica Redis; Range membership is hydrated from each process’s own stream poll into its LAPI Client cache.
**Migration**: Each replica must poll LAPI for its bouncer row; no shared `range-index` across processes.
