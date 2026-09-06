## MODIFIED Requirements

### Requirement: GetRemoteIP walks forwarded hops then RemoteAddr
`pkg/ip.GetRemoteIP` SHALL be the owner of the client address. It SHALL walk the custom forwarded-header value from most recent hop to oldest, skip hops that sit in the trusted-hop pool (`ForwardedHeadersTrustedIPs`), and return the first address that is not in that pool. When the header is empty or every hop is trusted, it SHALL return the host from `req.RemoteAddr`. When that chosen address is a parseable IP, GetRemoteIP SHALL also yield it as `net.IP` (the XFF walk SHALL keep the winning hop’s parse; the RemoteAddr fallback SHALL parse after splitting host and port). Callers MUST reuse that string and that `net.IP`; they MUST NOT parse `RemoteAddr` again and MUST NOT parse the chosen string again for trusted-client membership. Empty header segments SHALL be skipped. A `RemoteAddr` that is not host:port SHALL fail.

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

## ADDED Requirements

### Requirement: Trusted-client check uses the parsed GetRemoteIP address
When GetRemoteIP yields a parsed `net.IP`, trusted-client membership SHALL use `ContainsIP` on that value. It MUST NOT call `Contains` on the client string. When GetRemoteIP succeeds and the chosen address is not a parseable IP, the bouncer SHALL treat that as trusted-IP checker failure (`plugin:tech_trustipfail`), not as an untrusted client that continues.

#### Scenario: Parsed client in the trusted pool
- **WHEN** GetRemoteIP yields `10.1.2.3` as `net.IP` and `ClientTrustedIPs` contains `10.0.0.0/8`
- **THEN** the request is treated as a trusted client without parsing the string again

#### Scenario: Unparseable chosen address fails the trusted-IP check
- **WHEN** GetRemoteIP succeeds with a chosen address that is not a parseable IP
- **THEN** the bouncer remediates as trusted-IP checker failure
