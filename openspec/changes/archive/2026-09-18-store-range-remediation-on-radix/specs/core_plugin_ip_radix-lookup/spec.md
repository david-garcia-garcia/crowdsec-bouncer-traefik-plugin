## MODIFIED Requirements

### Requirement: Range membership may reuse boolean CIDR prefix lookup
Stream and alone Range matching MAY use the same CIDR prefix membership as the trusted-IP pool. A Range helper endpoint MAY store the remediation string (letter, optional unit-separator origin) of that CIDR. The trusted-IP pool MUST NOT store a remediation payload. Boolean insert and boolean membership SHALL stay available for the trusted-IP pool. Ban and captcha SHALL be separate sets so longest-prefix-wins cannot hide a containing ban behind a longer captcha. Range membership MUST NOT live in the trusted-IP Checker. Public trusted-IP config keys SHALL stay `forwardedHeadersTrustedIps` and `clientTrustedIps`. When two Range CIDRs of the same kind occupy the same remapped prefix endpoint, the last successful insert SHALL win.

#### Scenario: Range ban still matches by CIDR containment
- **WHEN** stream has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden even though the trusted-IP pool uses prefix lookup

#### Scenario: Captcha prefix does not hide a containing ban
- **WHEN** stream has a Range ban `10.0.0.0/8` and a Range captcha `10.1.0.0/16` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden, not captcha

#### Scenario: Range endpoint returns the stored origin
- **WHEN** stream has a Range ban `10.0.0.0/8` whose stored string is `t` plus a unit-separator and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** Range membership returns that stored string

#### Scenario: Same remapped endpoint keeps the last insert
- **WHEN** stream has Range bans `0.0.0.0/0` then `::ffff:0:0/96` with different stored origins and the client IP is `192.0.2.1`
- **THEN** Range membership returns the stored string of `::ffff:0:0/96`

## ADDED Requirements

### Requirement: Range hit reads the stored string from the winning prefix
When a Range helper contains the client IP, membership SHALL return the stored string already held on the longest matching prefix of that helper. It MUST NOT re-parse stored CIDR text to recover that string. Boolean membership for the trusted-IP pool SHALL ignore any stored string.

#### Scenario: Overlapping bans keep the longest-prefix stored string
- **WHEN** a Range helper holds `10.0.0.0/8` stored as `t` plus origin `crowdsec` and `10.1.0.0/16` stored as `t` plus origin `cscli` and the query is `10.1.2.3`
- **THEN** the returned string is the `/16` stored value

#### Scenario: Trusted-IP membership stays boolean
- **WHEN** the trusted-IP pool contains `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** membership is true and no remediation string is required
