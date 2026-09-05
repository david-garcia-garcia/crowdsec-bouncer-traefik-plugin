## Purpose

Trusted-IP and trusted-CIDR membership answers in time bounded by address size, not by how many networks the operator listed, without changing public config. Stream and alone Range may reuse boolean CIDR prefix membership without storing a remediation on that helper.

## Requirements

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

### Requirement: Range membership may reuse boolean CIDR prefix lookup
Stream and alone Range matching MAY use the same boolean CIDR prefix membership as the trusted-IP pool. That membership MUST NOT store a remediation payload. Ban and captcha SHALL be separate sets so longest-prefix-wins cannot hide a containing ban behind a longer captcha. Range membership MUST NOT live in the trusted-IP Checker. Public trusted-IP config keys SHALL stay `forwardedHeadersTrustedIps` and `clientTrustedIps`.

#### Scenario: Range ban still matches by CIDR containment
- **WHEN** stream has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden even though the trusted-IP pool uses prefix lookup

#### Scenario: Captcha prefix does not hide a containing ban
- **WHEN** stream has a Range ban `10.0.0.0/8` and a Range captcha `10.1.0.0/16` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden, not captcha

### Requirement: Catch-all CIDRs stay same-family
Trusted-pool membership SHALL follow `net.IPNet.Contains` address-family rules. `0.0.0.0/0` SHALL NOT match IPv6. `::/0` SHALL NOT match IPv4.

#### Scenario: IPv4 catch-all does not trust IPv6
- **WHEN** `ClientTrustedIPs` contains `0.0.0.0/0` and the client IP is `2001:db8::1`
- **THEN** the request is not treated as a trusted client

#### Scenario: IPv6 catch-all does not trust IPv4
- **WHEN** `ClientTrustedIPs` contains `::/0` and the client IP is `203.0.113.10`
- **THEN** the request is not treated as a trusted client

### Requirement: Client IP still comes from GetRemoteIP
Trusted-pool membership SHALL classify the address already produced by `pkg/ip.GetRemoteIP`. It MUST NOT parse `RemoteAddr` a second time to feed the prefix structure.

#### Scenario: Forwarded client is the trusted-pool input
- **WHEN** a trusted hop forwards `X-Forwarded-For` for `10.1.2.3` and that address is in `ClientTrustedIPs`
- **THEN** trusted-client bypass uses `10.1.2.3`

### Requirement: GetRemoteIP walks forwarded hops then RemoteAddr
`pkg/ip.GetRemoteIP` SHALL be the owner of the client address. It SHALL walk the custom forwarded-header value from most recent hop to oldest, skip hops that sit in the trusted-hop pool (`ForwardedHeadersTrustedIPs`), and return the first address that is not in that pool. When the header is empty or every hop is trusted, it SHALL return the host from `req.RemoteAddr`. Callers MUST reuse that string; they MUST NOT parse `RemoteAddr` again. Empty header segments SHALL be skipped. A `RemoteAddr` that is not host:port SHALL fail.

#### Scenario: Trusted hops skipped, client kept
- **WHEN** the custom header is `203.0.113.10, 10.0.0.1` and `10.0.0.1` is in the trusted-hop pool
- **THEN** `GetRemoteIP` returns `203.0.113.10`

#### Scenario: Empty header uses RemoteAddr
- **WHEN** the custom header is missing and `RemoteAddr` is `192.0.2.1:12345`
- **THEN** `GetRemoteIP` returns `192.0.2.1`

#### Scenario: All hops trusted uses RemoteAddr
- **WHEN** the custom header is `10.0.0.1`, that address is in the trusted-hop pool, and `RemoteAddr` is `192.0.2.9:80`
- **THEN** `GetRemoteIP` returns `192.0.2.9`

#### Scenario: RemoteAddr without port fails
- **WHEN** the custom header is empty and `RemoteAddr` is `192.0.2.1` with no port
- **THEN** `GetRemoteIP` returns an error

