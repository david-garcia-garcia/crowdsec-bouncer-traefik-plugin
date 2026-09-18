## ADDED Requirements

### Requirement: Range hit recovers stored remediation from the winning prefix
When in-process Range membership remediates a client IP, it SHALL return the stored string already held on the winning prefix of the matching ban or captcha set. It MUST NOT re-parse stored CIDR text on that request. Nil or empty membership SHALL still be a miss. Ban SHALL still win over captcha. The client address SHALL remain the `net.IP` already produced by `pkg/ip.GetRemoteIP`. The `range-index` blob format SHALL stay `cidr=remediation` lines.

#### Scenario: Suffixed Range hit returns the stored origin
- **WHEN** membership holds `10.0.0.0/8=` plus `t` plus a unit-separator and `crowdsec` and the client IP is `10.1.2.3`
- **THEN** remediation is that stored string

#### Scenario: Longer ban prefix wins the origin
- **WHEN** membership holds a wide ban with origin `crowdsec` and a narrower ban with origin `cscli` that both contain the client IP
- **THEN** remediation is the narrower stored string

#### Scenario: Nil membership is a miss
- **WHEN** membership is nil
- **THEN** Range matching does not remediate
