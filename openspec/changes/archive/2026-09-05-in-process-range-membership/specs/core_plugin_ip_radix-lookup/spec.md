## REMOVED Requirements

### Requirement: Range remediation stays a per-network walk
**Reason**: Stream and alone Range lookup now uses in-process boolean CIDR membership rebuilt from `range-index`. Walking every blob line on the request path was the cost this change removes.
**Migration**: Range containment and ban-wins stay in `core_plugin_decisions_scopes`. Trusted-IP Checker is unchanged.

## ADDED Requirements

### Requirement: Range membership may reuse boolean CIDR prefix lookup
Stream and alone Range matching MAY use the same boolean CIDR prefix membership as the trusted-IP pool. That membership MUST NOT store a remediation payload. Ban and captcha SHALL be separate sets so longest-prefix-wins cannot hide a containing ban behind a longer captcha. Range membership MUST NOT live in the trusted-IP Checker. Public trusted-IP config keys SHALL stay `forwardedHeadersTrustedIps` and `clientTrustedIps`.

#### Scenario: Range ban still matches by CIDR containment
- **WHEN** stream has a Range ban `10.0.0.0/8` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden even though the trusted-IP pool uses prefix lookup

#### Scenario: Captcha prefix does not hide a containing ban
- **WHEN** stream has a Range ban `10.0.0.0/8` and a Range captcha `10.1.0.0/16` and the client IP is `10.1.2.3`
- **THEN** the request is forbidden, not captcha
