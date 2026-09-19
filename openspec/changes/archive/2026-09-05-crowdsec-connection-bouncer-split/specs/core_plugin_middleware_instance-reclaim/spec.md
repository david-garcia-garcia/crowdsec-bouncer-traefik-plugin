## Purpose

Traefik plugin `New` binds a Crowdsec connection incarnation through reclaim and returns a per-router bouncer so one Traefik process can run two independent Crowdsec configs at once.

## ADDED Requirements

### Requirement: Yaegi constructors stay on the module-root package
The plugin SHALL export `CreateConfig` and `New` from the package Traefik loads for `.traefik.yml` `import` (the module root). `New` SHALL take Traefik’s constructor context and MUST NOT ignore it.

#### Scenario: Catalog import still constructs
- **WHEN** Traefik loads `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`
- **THEN** `CreateConfig` and `New` exist on that package
- **AND** `New` receives a non-ignored context used as the reclaim holder

### Requirement: Connection is reclaimed by connection fields not middleware name
`New` SHALL open the process reclaim table with a key derived from Crowdsec connection fields (mode, LAPI/CAPI, redis, update and metrics intervals, AppSec client settings, HTTP timeout). The Traefik middleware name, `next`, ban/captcha templates, trusted IPs, and Enabled MUST NOT be in that key. The stored value SHALL be the Crowdsec connection (stream ticker, isolated cache, LAPI HTTP). `New` SHALL return a bouncer that holds `next` and that connection. Client address SHALL come from `pkg/ip.GetRemoteIP`; the connection MUST NOT parse `RemoteAddr`.

#### Scenario: Same backend two names share one connection
- **WHEN** two `New` calls use the same connection fields and different middleware names, each with a live constructor context
- **THEN** both bouncers use the same connection incarnation
- **AND** only one stream ticker is running for that key

#### Scenario: Different backends are isolated in one process
- **WHEN** two `New` calls use different LAPI hosts (or other connection fields) in one process
- **THEN** two connection incarnations exist
- **AND** a decision present only on the first LAPI remediates only the first bouncer
- **AND** the second bouncer’s cache does not contain that decision

### Requirement: Unreclaimed connection is closed after grace
When no live constructor context remains for a connection key and grace elapses, the connection SHALL stop its tickers and release idle HTTP connections (`Close`). A later `New` with the same connection fields SHALL construct a new incarnation.

#### Scenario: Reload within grace reuses the ticker
- **WHEN** every bound constructor context for a key is cancelled
- **AND** a `New` with the same connection fields runs before grace ends
- **THEN** the same connection incarnation is returned
- **AND** stream polling is not started a second time

### Requirement: Bouncer does not own the stream
The per-router bouncer SHALL handle request policy (trusted IPs, ban/captcha pages, whether AppSec runs on pass) and MUST NOT start a process-wide stream ticker.

#### Scenario: First-wins globals are gone
- **WHEN** two live configs disagree on update interval
- **THEN** each connection uses the interval from its own config
- **AND** neither overwrites the other’s ticker
