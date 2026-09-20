## Purpose

Keeps request-path Debug from formatting a string unless Debug is enabled, while still logging the same fields.

## Requirements

### Requirement: Request-path Debug does not format unless Debug is enabled
On the request hot path, Debug SHALL NOT evaluate a format string (`fmt.Sprintf` or equivalent concatenation that builds the log message) unless the logger's level includes Debug. Debug SHALL pass the existing fields as slog attributes (or an Enabled check before any format). Fields that DestBranch already logs MUST remain: ServeHTTP `ip` and `isTrusted`. This leaf MUST NOT require `cache.Client` Get/GetMany/Set/Delete Debug stems. The client address SHALL reuse `GetRemoteIP` / `clientRequest.remoteIP`. Trusted-client membership SHALL reuse the trusted-client Checker `ContainsIP` result. Message stem `ServeHTTP` MUST stay recognizable. Construct-time logger destination and format (`std_go_logger_slog-output`) MUST NOT change. Default `logLevel` MUST NOT change.

#### Scenario: INFO allow does not emit request-path Debug
- **WHEN** a stream-mode request is allowed with the logger at INFO
- **THEN** no Debug record is emitted for ServeHTTP

#### Scenario: DEBUG ServeHTTP keeps ip and isTrusted as attributes
- **WHEN** ServeHTTP runs with the logger at DEBUG
- **THEN** the Debug record message is `ServeHTTP`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `isTrusted` equal to the trusted-client Checker result
