## ADDED Requirements

### Requirement: Construct-time Bouncer initialized lists trusted IPs
When bouncer construction succeeds, DEBUG SHALL emit one record whose message is `Bouncer initialized`. That record SHALL include attribute `forwardedHeadersTrustedIPs` equal to the forwarded-headers trusted-IP config slice as written, and attribute `clientTrustedIPs` equal to the client trusted-IP config slice as written. Bare hosts SHALL stay bare on that line; they MUST NOT be rewritten to `/32` or `/128`. Empty or nil slices SHALL still appear as empty lists. The record MUST reuse those Config slices already in hand at construction; it MUST NOT re-derive hops or the client address. Default `logLevel` and logger destination or format MUST NOT change. Request-path TRACE SHALL stay out of this requirement.

#### Scenario: CIDRs and a bare host on one line
- **WHEN** bouncer construction succeeds with a forwarded-headers list that contains CIDRs and a bare host, and a client list that contains CIDRs
- **THEN** one DEBUG record message is `Bouncer initialized`
- **AND** `forwardedHeadersTrustedIPs` equals those forwarded-headers strings as written
- **AND** `clientTrustedIPs` equals those client strings as written

#### Scenario: Empty lists still log both attrs
- **WHEN** bouncer construction succeeds with empty forwarded-headers and empty client trusted-IP lists
- **THEN** one DEBUG record message is `Bouncer initialized`
- **AND** both attributes are present as empty lists

#### Scenario: Two pools stay distinct
- **WHEN** the forwarded-headers list and the client list differ
- **THEN** the two attributes keep those distinct slices
- **AND** they MUST NOT be merged into one list
