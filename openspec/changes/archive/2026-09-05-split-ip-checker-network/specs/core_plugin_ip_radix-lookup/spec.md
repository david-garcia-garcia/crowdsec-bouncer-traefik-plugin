## ADDED Requirements

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
