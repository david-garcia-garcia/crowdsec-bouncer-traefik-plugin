## MODIFIED Requirements

### Requirement: Ip cache lookup key matches store canonicalization
Ip-scoped stream decisions SHALL be stored under `IPCacheKey(decision.Value)`. Request-path Ip lookup SHALL use the same canonical key derived from the client address GetRemoteIP already yielded: when `IPCacheKey(remoteIP)` canonicalizes a CIDR, use that key; otherwise use the parsed `net.IP` string with IPv4-mapped addresses collapsed via `To4()` when non-nil; otherwise the trimmed raw string. Alternate IPv6 spellings and IPv4-mapped forms of the same address SHALL hit the same cache entry as the stored decision.

#### Scenario: Expanded IPv6 header matches compressed store key
- **WHEN** stream stored an Ip ban under key `2001:db8::1` (from `2001:db8::1/128`) and the request header yields expanded `2001:db8:0:0:0:0:0:1` with the same parsed IP
- **THEN** Ip-scope lookup hits the ban

#### Scenario: IPv4-mapped header matches IPv4 store key
- **WHEN** stream stored an Ip ban under key `203.0.113.10` (from `203.0.113.10/32`) and GetRemoteIP yields `::ffff:203.0.113.10` as the raw string with parsed IPv4 `203.0.113.10`
- **THEN** Ip-scope lookup hits the ban

### Requirement: Range index apply aborts on unreachable read
When `ApplyRangeBatch` cannot read the existing `range-index` blob because the cache is unreachable, it SHALL return an error and MUST NOT write or delete `range-index`. A genuine cache miss SHALL still start from an empty index and apply normally.

#### Scenario: Unreachable read preserves existing index
- **WHEN** Redis returns `cache:unreachable` on `Get(range-index)` and a stream poll would upsert a new Range CIDR
- **THEN** `ApplyRangeBatch` fails and the prior `range-index` content is unchanged

#### Scenario: Cache miss still applies upserts
- **WHEN** `Get(range-index)` returns `cache:miss` and the poll upserts `10.0.0.0/8=t`
- **THEN** `range-index` is written with that line
