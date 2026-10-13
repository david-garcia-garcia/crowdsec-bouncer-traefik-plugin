## MODIFIED Requirements

### Requirement: Range decisions match by CIDR containment
When a decision scope is `Range` (any case), the bouncer SHALL treat `value` as a CIDR and remediate a request whose client IP is inside that network. A parseable bare IP SHALL be that host as `/32` (IPv4) or `/128` (IPv6). Range membership SHALL be stored on one shared cache key `range-index` as `cidr=remediation` lines so Redis replicas that only read can still match. When several containing CIDRs hit, `ban` SHALL win over `captcha`. In stream and alone modes, the request path SHALL match Range from in-process membership rebuilt from that blob and MUST NOT read `range-index` on the request. live and none SHALL keep skipping `range-index` and expand Range via LAPI `?ip=`.

#### Scenario: Stream Range contains the client
- **WHEN** stream or alone mode has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden

#### Scenario: IP outside the Range still passes
- **WHEN** only that Range ban exists and the client IP is `203.0.113.10`
- **THEN** the request is allowed

#### Scenario: Redis replica that skipped LAPI still matches Range
- **WHEN** Redis holds a Range ban `10.0.0.0/8` on `range-index` and this instance skipped the stream poll because another instance already updated
- **THEN** a request from `10.1.2.3` is forbidden after this instance hydrates from the blob

#### Scenario: Empty Range membership is a miss
- **WHEN** stream mode has no Range decisions
- **THEN** Range matching does not remediate the request

#### Scenario: Bare Range host remediates that address
- **WHEN** stream or alone mode has a Range ban `192.0.2.1` and the client IP is `192.0.2.1`
- **THEN** the request is forbidden
