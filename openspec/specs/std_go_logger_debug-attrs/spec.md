## Purpose

Keeps request-path Debug from formatting a string unless Debug is enabled, while still logging the same fields.

## Requirements

### Requirement: Request-path Debug does not format unless Debug is enabled

On the request hot path, Debug SHALL NOT evaluate a format string (`fmt.Sprintf` or equivalent concatenation that builds the log message) unless the logger's level includes Debug. Debug SHALL pass the existing fields as slog attributes (or an Enabled check before any format). Fields that DestBranch already logs MUST remain: ServeHTTP `ip` and `isTrusted`; cache Get `key`; cache GetMany `keys`; cache Set `key`, `value`, and `duration`; cache Delete `key`. The client address SHALL reuse `GetRemoteIP` / `clientRequest.remoteIP`. Trusted-client membership SHALL reuse the trusted-client Checker `ContainsIP` result. Message stems MUST stay recognizable (`ServeHTTP`, `cache:Get`, `cache:GetMany`, `cache:Set`, `cache:Delete`). Construct-time logger destination and format (`std_go_logger_slog-output`) MUST NOT change. Default `logLevel` MUST NOT change.

#### Scenario: INFO allow does not emit request-path Debug

- **WHEN** a stream-mode request is allowed with the logger at INFO
- **THEN** no Debug record is emitted for ServeHTTP or cache Get/GetMany

#### Scenario: DEBUG ServeHTTP keeps ip and isTrusted as attributes

- **WHEN** ServeHTTP runs with the logger at DEBUG
- **THEN** the Debug record message is `ServeHTTP`
- **AND** the record includes attribute `ip` equal to the client address already chosen for that request
- **AND** the record includes attribute `isTrusted` equal to the trusted-client Checker result

#### Scenario: DEBUG cache Get keeps the key as an attribute

- **WHEN** `cache.Client` Get runs with the logger at DEBUG
- **THEN** the Debug record message is `cache:Get`
- **AND** the record includes attribute `key` equal to the lookup key

#### Scenario: DEBUG cache GetMany keeps the keys as an attribute

- **WHEN** `cache.Client` GetMany runs with the logger at DEBUG
- **THEN** the Debug record message is `cache:GetMany`
- **AND** the record includes attribute `keys` equal to the lookup keys
