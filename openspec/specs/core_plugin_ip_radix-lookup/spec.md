## Purpose

Trusted-IP and trusted-CIDR membership answers in time bounded by address size, not by how many networks the operator listed, without changing public config. Membership is the vendored utilities Helper (`github.com/david-garcia-garcia/traefik-middleware-utilities/iplookup`: `New`, `AddCIDR`, `Contains`), not an in-tree helper package. Stream and alone Range may reuse boolean CIDR prefix membership without storing a remediation on that helper.

## Requirements

### Requirement: IPv4-mapped CIDR insert remaps to IPv4 Contains
When a trusted-pool or Range-membership CIDR is parseable and IPv4-mapped (`To4()` non-nil and mask `bits==128`), insert SHALL remap the prefix to IPv4 length `ones-96` and store it on the IPv4 family root. Insert MUST NOT panic. Insert MUST NOT walk `ones` from bit 0 on the IPv6 root. After a successful insert, membership SHALL match `net.IPNet.Contains` for that network: IPv4 and IPv4-mapped addresses that sit in the remapped IPv4 prefix match; native IPv6 does not. Native IPv4 CIDRs (mask `bits==32`) and native IPv6 CIDRs (`To4()` nil) SHALL keep today's insert. Mapped prefixes that `ParseCIDR` already rewrites to native IPv6 SHALL stay unchanged. `AddCIDR` MUST NOT fail solely because the CIDR is IPv4-mapped. Config validate SHALL return an error only for parse or construction failure; it MUST NOT abort the process. Client address ownership stays on `pkg/ip.GetRemoteIP`. Range-index keys SHALL stay as written; remapped prefix length is stored on the node only.

#### Scenario: Mapped slash-96 does not panic
- **WHEN** the helper inserts `::ffff:0:0/96`
- **THEN** insert returns without panic and `AddCIDR` succeeds

#### Scenario: Mapped slash-96 matches IPv4
- **WHEN** the helper has inserted `::ffff:0:0/96` and the query is `192.0.2.1`
- **THEN** membership is true

#### Scenario: Mapped slash-96 matches IPv4-mapped
- **WHEN** the helper has inserted `::ffff:0:0/96` and the query is `::ffff:192.0.2.1`
- **THEN** membership is true

#### Scenario: Mapped slash-96 misses native IPv6
- **WHEN** the helper has inserted `::ffff:0:0/96` and the query is `2001:db8::1` or `::1` or `::`
- **THEN** membership is false

#### Scenario: Mapped slash-120 matches as IPv4 slash-24
- **WHEN** the helper has inserted `::ffff:192.0.2.0/120` and the query is `192.0.2.10`
- **THEN** membership is true, matching `192.0.2.0/24`

#### Scenario: NewChecker accepts a mapped CIDR
- **WHEN** `NewChecker` is built with `::ffff:0:0/96`
- **THEN** construction succeeds and `Contains` of `192.0.2.1` is true

#### Scenario: Range membership inserts a mapped ban
- **WHEN** `MembershipFromIndex` is built with `::ffff:0:0/96=t` and the query is `192.0.2.1`
- **THEN** build does not panic and remediation is ban

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
Stream and alone Range matching MAY use the same boolean CIDR prefix membership as the trusted-IP pool (`github.com/david-garcia-garcia/traefik-middleware-utilities/iplookup`). That membership MUST NOT store a remediation payload on the Helper. Ban and captcha SHALL be separate boolean sets so longest-prefix-wins cannot hide a containing ban behind a longer captcha. Range membership MUST NOT live in the trusted-IP Checker. Public trusted-IP config keys SHALL stay `forwardedHeadersTrustedIps` and `clientTrustedIps`.

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

### Requirement: Trusted-client check uses the parsed GetRemoteIP address
When GetRemoteIP yields a parsed `net.IP`, trusted-client membership SHALL use `ContainsIP` on that value. It MUST NOT call `Contains` on the client string. When GetRemoteIP succeeds and the chosen address is not a parseable IP, the bouncer SHALL treat that as trusted-IP checker failure (`plugin:tech_trustipfail`), not as an untrusted client that continues.

#### Scenario: Parsed client in the trusted pool
- **WHEN** GetRemoteIP yields `10.1.2.3` as `net.IP` and `ClientTrustedIPs` contains `10.0.0.0/8`
- **THEN** the request is treated as a trusted client without parsing the string again

#### Scenario: Unparseable chosen address fails the trusted-IP check
- **WHEN** GetRemoteIP succeeds with a chosen address that is not a parseable IP
- **THEN** the bouncer remediates as trusted-IP checker failure

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
