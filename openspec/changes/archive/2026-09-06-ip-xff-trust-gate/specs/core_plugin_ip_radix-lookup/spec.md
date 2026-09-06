## MODIFIED Requirements

### Requirement: GetRemoteIP walks forwarded hops then RemoteAddr
`pkg/ip.GetRemoteIP` SHALL be the owner of the client address. Before walking the custom forwarded-header value, it SHALL verify the host extracted from `req.RemoteAddr` is in the trusted-hop pool (`ForwardedHeadersTrustedIPs` via `PoolStrategy.Checker`). When the pool is empty, the checker is nil, or the socket peer is not in the pool, GetRemoteIP SHALL ignore forwarded headers and return the host from `req.RemoteAddr` only. When the socket peer is trusted and the pool is non-empty, GetRemoteIP SHALL walk the custom forwarded-header value from most recent hop to oldest, skip hops that sit in the trusted-hop pool, and return the first address that is not in that pool. When the header is empty or every hop is trusted, it SHALL return the host from `req.RemoteAddr`. When that chosen address is a parseable IP, GetRemoteIP SHALL also yield it as `net.IP` (the XFF walk SHALL keep the winning hop's parse; the RemoteAddr fallback SHALL parse after splitting host and port). Callers MUST reuse that string and that `net.IP`; they MUST NOT parse `RemoteAddr` again and MUST NOT parse the chosen string again for trusted-client membership. Empty header segments SHALL be skipped. A `RemoteAddr` that is not host:port SHALL fail.

#### Scenario: Trusted RemoteAddr required for header walk
- **WHEN** the custom header is `203.0.113.10, 10.0.0.1`, `10.0.0.1` is in the trusted-hop pool, and `RemoteAddr` is `10.0.0.1:443`
- **THEN** `GetRemoteIP` returns `203.0.113.10`

#### Scenario: Untrusted RemoteAddr ignores forged header
- **WHEN** the custom header is `203.0.113.10, 10.0.0.1`, `10.0.0.1` is in the trusted-hop pool, and `RemoteAddr` is `198.51.100.5:443`
- **THEN** `GetRemoteIP` returns `198.51.100.5`

#### Scenario: Empty trusted pool ignores header
- **WHEN** the trusted-hop pool is empty, the custom header is `203.0.113.10`, and `RemoteAddr` is `198.51.100.5:443`
- **THEN** `GetRemoteIP` returns `198.51.100.5`

#### Scenario: Empty header uses RemoteAddr
- **WHEN** the custom header is missing and `RemoteAddr` is `192.0.2.1:12345`
- **THEN** `GetRemoteIP` returns `192.0.2.1`

#### Scenario: All hops trusted uses RemoteAddr
- **WHEN** the custom header is `10.0.0.1`, that address is in the trusted-hop pool, and `RemoteAddr` is `192.0.2.9:80`
- **THEN** `GetRemoteIP` returns `192.0.2.9`

#### Scenario: RemoteAddr without port fails
- **WHEN** the custom header is empty and `RemoteAddr` is `192.0.2.1` with no port
- **THEN** `GetRemoteIP` returns an error

#### Scenario: Unparseable hop fails closed
- **WHEN** the custom header is `203.0.113.10, not-an-ip, 10.0.0.1`, `10.0.0.1` is trusted, and `RemoteAddr` is `10.0.0.1:443`
- **THEN** `GetRemoteIP` returns `not-an-ip` with nil `net.IP`
