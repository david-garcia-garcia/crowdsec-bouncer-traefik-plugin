## MODIFIED Requirements

### Requirement: Range hit recovers stored remediation from the winning prefix
When in-process Range membership remediates a client IP, it SHALL return the utilities Helper metadata already held on the winning prefix of the matching ban or captcha set. It MUST NOT re-parse `storedByCIDR` on that request. Nil or empty membership SHALL still be a miss. Ban SHALL still win over captcha. Range metadata SHALL be `KindOriginString` (kind plus optional newline origin). The client address SHALL remain the `net.IP` already produced by `pkg/ip.GetRemoteIP`. The `range-index` blob format SHALL stay `cidr=kind` plus optional origin line. Ban and captcha MUST stay on separate Helpers. `Helper.Contains` and `Count` SHALL use the published utilities RLock (`traefik-middleware-utilities` v1.0.7). IPv4 `familyWalk` SHALL be the published four-byte walk. This plugin MUST NOT re-patch `vendor/.../iplookup`.

#### Scenario: Suffixed Range hit returns the stored origin
- **WHEN** membership holds `10.0.0.0/8=t` then a newline and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** remediation is that stored string

#### Scenario: Longer ban prefix wins the origin
- **WHEN** membership holds a wide ban with origin `crowdsec` and a narrower ban with origin `cscli` that both contain the client IP
- **THEN** remediation is the narrower stored string
