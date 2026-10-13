## ADDED Requirements

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
