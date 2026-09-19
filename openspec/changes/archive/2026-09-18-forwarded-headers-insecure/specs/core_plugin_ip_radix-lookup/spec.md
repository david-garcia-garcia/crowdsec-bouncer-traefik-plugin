## MODIFIED Requirements

### Requirement: GetRemoteIP walks forwarded hops then RemoteAddr
Unless `ForwardedHeadersInsecure` is true, `pkg/ip.GetRemoteIP` SHALL be the owner of the client address. Before walking the custom forwarded-header value, it SHALL verify the host extracted from `req.RemoteAddr` is in the trusted-hop pool (`ForwardedHeadersTrustedIPs` via `PoolStrategy.Checker`). When the pool is empty, the checker is nil, or the socket peer is not in the pool, GetRemoteIP SHALL ignore forwarded headers and return the host from `req.RemoteAddr` only. When the socket peer is trusted and the pool is non-empty, GetRemoteIP SHALL walk the custom forwarded-header value from most recent hop to oldest, skip hops that sit in the trusted-hop pool, and return the first address that is not in that pool. When the header is empty or every hop is trusted, it SHALL return the host from `req.RemoteAddr`. When that chosen address is a parseable IP, GetRemoteIP SHALL also yield it as `net.IP` (the XFF walk SHALL keep the winning hop's parse; the RemoteAddr fallback SHALL parse after splitting host and port). Callers MUST reuse that string and that `net.IP`; they MUST NOT parse `RemoteAddr` again and MUST NOT parse the chosen string again for trusted-client membership. Empty header segments SHALL be skipped. A `RemoteAddr` that is not host:port SHALL fail.

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

#### Scenario: Catch-all pool ignores the header
- **WHEN** the trusted-hop pool is `0.0.0.0/0` plus `::/0`, `RemoteAddr` is `203.0.113.7:443`, and `X-Real-Ip` is `198.51.100.9`
- **THEN** `GetRemoteIP` returns `203.0.113.7`

#### Scenario: RemoteAddr without port fails
- **WHEN** the custom header is empty and `RemoteAddr` is `192.0.2.1` with no port
- **THEN** `GetRemoteIP` returns an error

#### Scenario: Unparseable hop fails closed
- **WHEN** the custom header is `203.0.113.10, not-an-ip, 10.0.0.1`, `10.0.0.1` is trusted, and `RemoteAddr` is `10.0.0.1:443`
- **THEN** `GetRemoteIP` returns `not-an-ip` with nil `net.IP`

## ADDED Requirements

### Requirement: ForwardedHeadersInsecure reads the header as a single client address
When `ForwardedHeadersInsecure` is true, `pkg/ip.GetRemoteIP` SHALL still require `req.RemoteAddr` to be host:port and SHALL fail with `GetRemoteIP:extractIP` when it is not. It MUST NOT call `getIP` and MUST NOT consult `PoolStrategy.Checker`. It SHALL read the whole trimmed value of the custom header without splitting on commas. An absent, empty, or whitespace-only header SHALL return the host from `RemoteAddr` (parsed when possible). A value that parses as a bare IP SHALL return that string and its `net.IP`. Any other value, including a comma-separated list, a port suffix, a bracketed IPv6 address, or garbage, SHALL return the raw trimmed string with a nil `net.IP`. A non-empty `ForwardedHeadersTrustedIPs` MUST NOT change this path. `ClientTrustedIPs` SHALL still apply to the chosen address. When the flag is on and `ForwardedHeadersCustomName` still holds the default `X-Forwarded-For`, `bouncer.New` SHALL set the effective header to `X-Real-Ip` and log that name once at Info; any other configured name SHALL be used as written.

#### Scenario: Insecure absent header uses RemoteAddr
- **WHEN** `ForwardedHeadersInsecure` is true, the custom header is missing, and `RemoteAddr` is `203.0.113.7:443`
- **THEN** `GetRemoteIP` returns `203.0.113.7`

#### Scenario: Insecure header wins for an untrusted peer
- **WHEN** `ForwardedHeadersInsecure` is true, the trusted-hop pool is empty, `RemoteAddr` is `203.0.113.7:443`, and `X-Real-Ip` is `198.51.100.9`
- **THEN** `GetRemoteIP` returns `198.51.100.9`

#### Scenario: Insecure header wins despite a catch-all pool
- **WHEN** `ForwardedHeadersInsecure` is true, the trusted-hop pool is `0.0.0.0/0` plus `::/0`, `RemoteAddr` is `203.0.113.7:443`, and `X-Real-Ip` is `198.51.100.9`
- **THEN** `GetRemoteIP` returns `198.51.100.9`

#### Scenario: Insecure comma list fails closed
- **WHEN** `ForwardedHeadersInsecure` is true and the custom header is `203.0.113.10, 10.0.0.1`
- **THEN** `GetRemoteIP` returns `203.0.113.10, 10.0.0.1` with nil `net.IP`

#### Scenario: Insecure unparseable value fails closed
- **WHEN** `ForwardedHeadersInsecure` is true and the custom header is `203.0.113.10:443` or `[2001:db8::1]` or `not-an-ip`
- **THEN** `GetRemoteIP` returns the raw trimmed string with nil `net.IP`

#### Scenario: Insecure RemoteAddr without port still fails
- **WHEN** `ForwardedHeadersInsecure` is true, the custom header is `198.51.100.9`, and `RemoteAddr` is `192.0.2.1` with no port
- **THEN** `GetRemoteIP` returns an error

#### Scenario: Default custom name becomes X-Real-Ip
- **WHEN** `ForwardedHeadersInsecure` is true and `ForwardedHeadersCustomName` is still `X-Forwarded-For`
- **THEN** `bouncer.New` stores `X-Real-Ip` as the effective header

#### Scenario: Explicit custom name is unchanged
- **WHEN** `ForwardedHeadersInsecure` is true and `ForwardedHeadersCustomName` is `CF-Connecting-IP`
- **THEN** `bouncer.New` stores `CF-Connecting-IP` as the effective header
