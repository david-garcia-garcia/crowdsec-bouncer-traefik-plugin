## Purpose

Keeps request-path Trace from formatting a string unless Trace is enabled, while still logging the same fields.

## Requirements

### Requirement: Request-path Trace does not format unless Trace is enabled
On the request hot path, Trace SHALL NOT evaluate a format string (`fmt.Sprintf` or equivalent concatenation that builds the log message) unless the logger's level includes Trace. Trace SHALL pass the existing fields as slog attributes (or an Enabled check before any format). Fields that DestBranch already logs MUST remain: ServeHTTP `ip` and `isTrusted`. This leaf MUST NOT require `cache.Client` Get/GetMany/Set/Delete Debug stems. The client address SHALL reuse `GetRemoteIP` / `clientRequest.remoteIP`. Trusted-client membership SHALL reuse the trusted-client Checker `ContainsIP` result. Message stem `ServeHTTP` MUST stay recognizable. Construct-time logger destination and format (`std_go_logger_slog-output`) MUST NOT change. Default `logLevel` MUST NOT change. Per-request ServeHTTP breadcrumbs and captcha Check/Validate SHALL log at Trace, not Debug. Failure lines on that path (lookup error, drain, parse, too-large body, AppSec error, stream unhealthy) SHALL stay Debug. DEBUG SHALL still emit construct-time and stream-tick Debug.

#### Scenario: INFO allow does not emit request-path Trace
- **WHEN** a stream-mode request is allowed with the logger at INFO
- **THEN** no Trace record is emitted for ServeHTTP

#### Scenario: DEBUG allow does not emit request-path Trace
- **WHEN** a stream-mode request is allowed with the logger at DEBUG
- **THEN** no Trace record is emitted for ServeHTTP

#### Scenario: TRACE ServeHTTP keeps ip and isTrusted as attributes
- **WHEN** ServeHTTP runs with the logger at TRACE
- **THEN** the Trace record message is `ServeHTTP`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `isTrusted` equal to the trusted-client Checker result

### Requirement: Remediating TRACE shows mapped scopes in play
When ServeHTTP remediates from a live, stream, or alone store hit, the remediating TRACE record message SHALL be `ServeHTTP`. That record SHALL include attribute `ip` equal to the client address already chosen for that request (`GetRemoteIP` / `clientRequest.remoteIP`) and attribute `remediation` equal to the remediation letter. It MUST NOT include attribute `cache`. It MUST NOT present the hit as a cache hit. When `RequestScopeValues` already collected for that request has present entries, the record SHALL include slog group `scopes` whose keys are those CrowdSec scope names and whose values are those header values. Missing mapped headers SHALL be omitted. The record MUST reuse that already-collected map; it MUST NOT re-read request headers and MUST NOT re-parse `RemoteAddr`. The record MUST NOT add a winning-scope field. The record MUST NOT log a Range CIDR. When no mapped header is present, the record MUST NOT invent scope keys. The first TRACE `ServeHTTP` breadcrumb (stem, `ip`, `isTrusted`) SHALL stay; that breadcrumb MUST NOT be required to include `scopes`. When live or none remediates after `LiveLookup`, TRACE `ServeHTTP:LiveLookup` SHALL include the same `ip`, the same `scopes` group when present, and the existing kind attribute `isBanned`. `handleRemediationServeHTTP` TRACE SHALL stay `ip` and `remediation`. DEBUG `ServeHTTP:Get` `cache` SHALL stay. Default `logLevel` and logger destination or format MUST NOT change.

#### Scenario: TRACE remediating store hit drops cache and includes present scopes
- **WHEN** a stream-mode request remediates from a store hit with the logger at TRACE
- **AND** mapped Country and AS headers are present
- **THEN** a TRACE record message is `ServeHTTP`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `remediation` equal to the remediation letter
- **AND** the record MUST NOT include attribute `cache`
- **AND** the record includes group `scopes` with those present Country and AS values

#### Scenario: TRACE remediating store hit omits missing headers
- **WHEN** a stream-mode request remediates from a store hit with the logger at TRACE
- **AND** Country is mapped but the Country header is missing
- **THEN** the remediating `ServeHTTP` TRACE MUST NOT include a Country key under `scopes`

#### Scenario: TRACE first breadcrumb keeps ip and isTrusted without requiring scopes
- **WHEN** ServeHTTP runs with the logger at TRACE
- **THEN** a TRACE record message is `ServeHTTP`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `isTrusted` equal to the trusted-client Checker result
- **AND** that breadcrumb MUST NOT be required to include `scopes`

#### Scenario: TRACE LiveLookup remediating includes scopes and isBanned
- **WHEN** a live or none request remediates after `LiveLookup` with the logger at TRACE
- **AND** mapped scope headers are present
- **THEN** a TRACE record message is `ServeHTTP:LiveLookup`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `isBanned` equal to the remediation kind
- **AND** the record includes group `scopes` with those present mapped values
- **AND** the record MUST NOT include attribute `cache`

#### Scenario: TRACE remediating with no mapped headers invents no scope keys
- **WHEN** a stream-mode request remediates from a store hit with the logger at TRACE
- **AND** no mapped header is present
- **THEN** the remediating `ServeHTTP` TRACE includes `ip` and `remediation`
- **AND** the record MUST NOT include attribute `cache`
- **AND** the record MUST NOT invent scope keys
