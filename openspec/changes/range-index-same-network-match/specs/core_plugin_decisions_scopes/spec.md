## ADDED Requirements

### Requirement: Range index upsert and remove match the same network
`upsertIndexCIDR` and `removeCIDRFromIndex` SHALL treat two CIDR strings as the same `range-index` line when both parse as IP networks and the parsed network addresses are equal and the prefix lengths match (mask ones and bits). They MUST NOT compare `ParseCIDR`'s first (unmasked) IP. When either side fails to parse, they SHALL fall back to raw-text equality so identical unparseable lines still match. A same-network hit SHALL replace or drop every matching line. A replace or append SHALL persist the incoming CIDR text and MUST NOT rewrite that line to `(*net.IPNet).String()`. This leaf MUST NOT sweep-rewrite leftover spellings the call did not name. `ApplyRangeBatch` SHALL keep one read, removals then upserts, and one write; a failed GET that is not a miss SHALL still return and MUST NOT write.

#### Scenario: Different spelling of the same network is removed
- **WHEN** `AddRange` stores `10.1.2.0/8` as a ban and `RemoveRange` is called with `10.0.0.0/8`
- **THEN** `range-index` no longer holds that network
- **AND** membership for `10.1.2.3` is clear

#### Scenario: Same-network upsert persists the incoming spelling
- **WHEN** `range-index` holds `10.1.2.0/8=c` and `AddRange` upserts `10.0.0.0/8` as a ban
- **THEN** that line is replaced with the incoming text `10.0.0.0/8` plus the new remediation
- **AND** leftover lines this call did not name are left as they were

#### Scenario: Identical unparseable text still matches
- **WHEN** `range-index` holds an unparseable CIDR line and remove is called with that same raw text
- **THEN** that line is dropped

#### Scenario: Parseable and unparseable text are not the same line
- **WHEN** `range-index` holds `10.0.0.0/8=t` and remove is called with unparseable text that is not that string
- **THEN** the `10.0.0.0/8` line stays
