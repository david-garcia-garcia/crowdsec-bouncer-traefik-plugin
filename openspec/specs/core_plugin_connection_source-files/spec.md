## Purpose

CrowdsecConnection jobs live in named same-package files so each job has one owner file, while callers still use the same type and exported API.

## Requirements

### Requirement: Connection jobs live in named files
`package crowdsecconnection` SHALL keep `CrowdsecConnection` in `connection.go` and SHALL place AppSec, stream ticker, live lookup, LAPI/CAPI HTTP, and metrics in `connection_appsec.go`, `connection_stream.go`, `connection_live.go`, `connection_http.go`, and `connection_metrics.go` respectively. Reclaim identity SHALL stay in `identity.go`. Stream store/delete and live decision parse SHALL stay in `connection_decisions.go`. The package MUST NOT introduce a new module path for those jobs.

#### Scenario: Named files exist
- **WHEN** a developer opens `pkg/crowdsecconnection/`
- **THEN** `connection_appsec.go`, `connection_stream.go`, `connection_live.go`, `connection_http.go`, and `connection_metrics.go` exist
- **AND** `AppsecQuery` is declared in `connection_appsec.go`
- **AND** `LiveLookup` is declared in `connection_live.go`

### Requirement: Exported API stays on the same package
Callers SHALL keep importing `pkg/crowdsecconnection` for `Prepare`, `New`, `CrowdsecConnection`, `LiveLookup`, `AppsecQuery`, `Key`, and `IdentityHex`. Those identifiers MUST remain exported from that package.

#### Scenario: Bouncer still calls LiveLookup and AppsecQuery
- **WHEN** `pkg/bouncer` compiles against this package
- **THEN** `CrowdsecConnection.LiveLookup` and `CrowdsecConnection.AppsecQuery` resolve without a new import path
