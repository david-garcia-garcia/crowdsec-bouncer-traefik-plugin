## ADDED Requirements

### Requirement: Range-index write identity is the canonical network
Range-index upsert and remove SHALL identify a line by the canonical network (masked network address plus prefix length ones and bits), not by CIDR text. An upsert SHALL replace every existing line of that network and persist one `cidr=remediation` line whose CIDR is that network's canonical string. A remove SHALL drop every line of that network. Incoming unparseable CIDR text SHALL be skipped. A leftover non-canonical spelling of a network this write upserts or removes SHALL be treated as that network. Unrelated leftover spellings SHALL stay. An IPv4 network and an IPv4-mapped IPv6 network that share a canonical string SHALL remain distinct when their prefix ones or bits differ. Lookup keys (`range-index`, client IP, `scope:value`) MUST NOT change. Request-path Range membership SHALL keep matching by CIDR containment.

#### Scenario: Equivalent CIDR spelling deletes
- **WHEN** the blob holds a Range ban written as `10.1.2.0/8` and a remove is given `10.0.0.0/8`
- **THEN** a request from `10.1.2.3` is not remediating from that Range

#### Scenario: Equivalent CIDR spelling upserts
- **WHEN** the blob holds a Range captcha written as `10.1.2.0/8` and an upsert is given `10.0.0.0/8` as ban
- **THEN** the blob has one line for that network as ban and a request from `10.1.2.3` is banned

#### Scenario: Unparseable incoming CIDR is dropped
- **WHEN** a Range upsert is given CIDR text that is not a CIDR
- **THEN** the blob does not gain that line

#### Scenario: Unrelated leftover spelling stays
- **WHEN** the blob holds `10.1.2.0/8` as ban and a write upserts a different network
- **THEN** the leftover `10.1.2.0/8` line remains

#### Scenario: IPv4-mapped prefix stays distinct
- **WHEN** the blob holds `10.0.0.0/8` as ban and a remove is given `::ffff:10.0.0.0/104`
- **THEN** the `10.0.0.0/8` ban remains
