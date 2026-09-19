## Purpose

Trusted-IP and trusted-CIDR membership answers in time bounded by address size, not by how many networks the operator listed, without changing public config or Range remediation.

## ADDED Requirements

### Requirement: Trusted pool membership is prefix-bounded
The bouncer SHALL decide whether a client address is in `ForwardedHeadersTrustedIPs` or `ClientTrustedIPs` without scanning the configured list length on the request path. Membership SHALL be true when the address equals a listed host or sits inside a listed CIDR. Overlapping CIDRs SHALL still match (any containing network is enough). An empty list SHALL match nothing.

#### Scenario: Address inside a listed CIDR
- **WHEN** `ClientTrustedIPs` contains `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is treated as a trusted client

#### Scenario: Bare listed host still matches
- **WHEN** `ClientTrustedIPs` contains `192.0.2.1` (no prefix) and the client IP is `192.0.2.1`
- **THEN** the request is treated as a trusted client

#### Scenario: Address outside the pool
- **WHEN** `ClientTrustedIPs` contains `10.0.0.0/8` and the client IP is `203.0.113.10`
- **THEN** the request is not treated as a trusted client

#### Scenario: Empty pool
- **WHEN** `ClientTrustedIPs` is empty
- **THEN** no client IP is trusted by that list

### Requirement: Invalid trusted CIDR fails construction
Building the trusted-IP pool SHALL fail when an entry is neither a parseable IP nor a parseable CIDR. Public config key names SHALL stay `forwardedHeadersTrustedIps` and `clientTrustedIps`.

#### Scenario: Bad CIDR at validate
- **WHEN** config validate runs with `ClientTrustedIPs` containing `192.168.1.0/33`
- **THEN** validation returns an error

### Requirement: Range remediation stays a per-network walk
CrowdSec Range matching SHALL keep using the shared `range-index` blob and per-line CIDR tests. This capability MUST NOT require Range matching to share the trusted-IP prefix structure.

#### Scenario: Range ban still matches by CIDR line
- **WHEN** stream has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden even though the trusted-IP pool uses prefix lookup

### Requirement: Client IP still comes from GetRemoteIP
Trusted-pool membership SHALL classify the address already produced by `pkg/ip.GetRemoteIP`. It MUST NOT parse `RemoteAddr` a second time to feed the prefix structure.

#### Scenario: Forwarded client is the trusted-pool input
- **WHEN** a trusted hop forwards `X-Forwarded-For` for `10.1.2.3` and that address is in `ClientTrustedIPs`
- **THEN** trusted-client bypass uses `10.1.2.3`
