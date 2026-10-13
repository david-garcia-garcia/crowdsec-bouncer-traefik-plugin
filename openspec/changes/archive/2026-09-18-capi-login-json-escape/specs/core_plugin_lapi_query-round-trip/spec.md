## ADDED Requirements

### Requirement: CAPI login body is valid JSON
The CAPI watchers-login request body SHALL be a JSON object whose fields `machine_id`, `password`, and `scenarios` are the configured CAPI credentials already stored on the Client. After JSON decode, those values MUST equal those configured strings, including when a value contains a quote, backslash, or newline. The body MUST contain only those three fields. The body MUST NOT be built by interpolating those strings into a JSON template. A nil scenario list SHALL encode as JSON `null`. An empty scenario list SHALL encode as an empty JSON array. If the body cannot be encoded as JSON, the plugin SHALL return an error and MUST NOT POST a fallback template.

#### Scenario: Metacharacters survive encode and decode
- **WHEN** the configured machine id, password, and one scenario each contain a quote, a backslash, and a newline
- **THEN** the posted login body is valid JSON
- **AND** decoding it yields those same three configured values

#### Scenario: Empty scenario list is an empty array
- **WHEN** the configured scenario list is empty
- **THEN** the posted login body's `scenarios` field is an empty JSON array

#### Scenario: Nil scenario list is JSON null
- **WHEN** the configured scenario list is unset
- **THEN** the posted login body's `scenarios` field is JSON `null`

#### Scenario: Encode failure does not post a fallback
- **WHEN** the login body cannot be encoded as JSON
- **THEN** the call returns an error
- **AND** no watchers-login request is sent
