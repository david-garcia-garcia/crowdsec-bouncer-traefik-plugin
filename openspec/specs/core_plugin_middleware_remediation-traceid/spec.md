## Purpose

When the operator sets `RemediationTraceIDCustomName`, this plugin generates a CF-Ray–style TraceID for ban and captcha HTML pages, injects it as a response header, and exposes it in those templates as `{{ .TraceID }}` without a third-party Traefik trace plugin.

## Requirements

### Requirement: Empty knob disables built-in TraceID
`RemediationTraceIDCustomName` SHALL default to empty. When it is empty, the plugin MUST NOT generate a TraceID, MUST NOT set a built-in trace response header, and ban `{{ .TraceID }}` SHALL continue to come only from `TraceHeadersCustomName` incoming passthrough when that is configured.

#### Scenario: Both knobs empty
- **WHEN** `RemediationTraceIDCustomName` and `TraceHeadersCustomName` are empty
- **AND** the client is banned with a ban template
- **THEN** the ban response has no generated trace header
- **AND** the template `TraceID` field is unset

#### Scenario: Incoming passthrough still works when built-in is off
- **WHEN** `RemediationTraceIDCustomName` is empty
- **AND** `TraceHeadersCustomName` is `X-Trace`
- **AND** the client sends `X-Trace: 0123456789` and is banned
- **THEN** the ban body includes `0123456789` as `{{ .TraceID }}`
- **AND** the plugin does not set `X-Trace` as a response header from generation

### Requirement: Built-in ID is 16 lowercase hex
When `RemediationTraceIDCustomName` is non-empty, each ban HTML and captcha HTML response SHALL use one newly generated identifier of 16 lowercase hexadecimal characters from `crypto/rand` (8 bytes). The plugin MUST NOT copy `Cf-Ray`, `X-Request-ID`, or `TraceHeadersCustomName` from the request for that ID. The plugin MUST NOT append a data-center colo suffix.

#### Scenario: Ban page gets a generated hex ID
- **WHEN** `RemediationTraceIDCustomName` is `X-Trace-ID`
- **AND** the client is banned with a ban template that prints `{{ .TraceID }}`
- **THEN** the response header `X-Trace-ID` is 16 lowercase hex characters
- **AND** the body contains the same value as `{{ .TraceID }}`

#### Scenario: Captcha page gets a generated hex ID
- **WHEN** `RemediationTraceIDCustomName` is `X-Trace-ID`
- **AND** the client is served captcha HTML
- **THEN** the response header `X-Trace-ID` is 16 lowercase hex characters
- **AND** the captcha template `{{ .TraceID }}` is that same value

### Requirement: Built-in generation wins over incoming passthrough
When `RemediationTraceIDCustomName` is non-empty, `{{ .TraceID }}` and the configured response header SHALL be the generated ID even if `TraceHeadersCustomName` is also set and the client sent that request header.

#### Scenario: Both knobs set
- **WHEN** `RemediationTraceIDCustomName` is `X-Trace-ID` and `TraceHeadersCustomName` is `X-Trace`
- **AND** the client sends `X-Trace: from-client` and is banned
- **THEN** `{{ .TraceID }}` is the generated 16-hex ID, not `from-client`
- **AND** response header `X-Trace-ID` is that generated ID

### Requirement: Trace header only on ban and captcha HTML
The configured trace response header SHALL be set on ban responses (including HEAD) and captcha HTML. It MUST NOT be set on pass-through, on solved-captcha redirects, or on AppSec challenge relay bodies.

#### Scenario: Pass-through has no built-in trace header
- **WHEN** `RemediationTraceIDCustomName` is `X-Trace-ID`
- **AND** the client is allowed
- **THEN** the origin response does not carry a plugin-generated `X-Trace-ID`

#### Scenario: Solved captcha redirect has no built-in trace header
- **WHEN** `RemediationTraceIDCustomName` is `X-Trace-ID`
- **AND** captcha validation succeeds and the plugin redirects
- **THEN** that redirect does not include `X-Trace-ID` from built-in generation

### Requirement: RNG failure does not drop the remediation page
If `crypto/rand` fails while generating a TraceID, the plugin SHALL log a warning, omit the trace response header and `{{ .TraceID }}`, and still write the ban or captcha page.

#### Scenario: Ban still served when rand fails
- **WHEN** `RemediationTraceIDCustomName` is set
- **AND** random generation fails
- **AND** the client is banned with a ban template
- **THEN** the client still receives the ban status and body
- **AND** the configured trace header is absent
