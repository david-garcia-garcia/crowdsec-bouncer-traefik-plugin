## ADDED Requirements

### Requirement: IPv6 zone ID is stripped before membership parse
The parse that `Contains` and `GetRemoteIP` already share SHALL strip an RFC 4007 IPv6 zone (`%eth0`, `%12`) from an IPv6-looking address before deciding whether that address is a parseable IP. The yielded `net.IP` SHALL be the zone-free address. The public string `GetRemoteIP` returns SHALL stay the received host or hop text, including the zone when present. A hop that still has brackets (`[fe80::1%eth0]`) SHALL stay unparseable. An IPv4 string with `%` SHALL stay unparseable. `GetRemoteIP` remains the owner of the client address; callers MUST reuse its string and `net.IP` and MUST NOT parse `RemoteAddr` again.

#### Scenario: Zoned link-local is in the pool
- **WHEN** the trusted pool contains `fe80::/10` and `Contains` is called with `fe80::1%eth0`
- **THEN** membership is true

#### Scenario: Zoned RemoteAddr is a trusted hop
- **WHEN** the trusted-hop pool contains `fe80::/10`, `RemoteAddr` is `[fe80::1%eth0]:443`, and `X-Forwarded-For` is `203.0.113.10`
- **THEN** `GetRemoteIP` returns `203.0.113.10` and a parsed `net.IP`

#### Scenario: RemoteAddr fallback keeps the zone on the string
- **WHEN** the trusted-hop pool contains `fe80::/10`, `RemoteAddr` is `[fe80::1%eth0]:443`, and the custom header is missing
- **THEN** `GetRemoteIP` returns `fe80::1%eth0` and a parsed `net.IP` for `fe80::1`

#### Scenario: Zoned hop keeps the hop text
- **WHEN** the trusted-hop pool contains `10.0.0.1`, `RemoteAddr` is `10.0.0.1:443`, and the custom header is `fe80::1%eth0`
- **THEN** `GetRemoteIP` returns `fe80::1%eth0` and a parsed `net.IP` for `fe80::1`

#### Scenario: Bracketed hop stays fail-closed
- **WHEN** the trusted-hop pool contains `10.0.0.1`, `RemoteAddr` is `10.0.0.1:443`, and the custom header is `[fe80::1%eth0]`
- **THEN** `GetRemoteIP` returns `[fe80::1%eth0]` with nil `net.IP`
