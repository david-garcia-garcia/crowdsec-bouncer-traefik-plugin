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
