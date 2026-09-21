## MODIFIED Requirements

### Requirement: Live LAPI error uses CrowdsecLapiFailureAction
When a live (or none-mode) LAPI lookup fails, the plugin SHALL apply `crowdsecLapiFailureAction`: `passthrough` proceeds to the pass path; `ban` remediates as a ban; `captcha` uses the configured captcha client. Cached hits SHALL still apply before a live lookup. A failure of **any** query the lookup makes counts as a failed lookup: the client-address query and every mapped header-scope query alike. A header-scope query that errors MUST NOT be reported as "no decision on that scope". The lookup SHALL report it to the caller with a **non-active** remediation, exactly as a failed client-address query is reported, so the configured action decides. When a header-scope query fails, the lookup MUST NOT write a negative live-cache entry for that client address, so the unverified allow does not survive in cache. The failure SHALL be logged at a level an operator sees at the plugin's default log level, not at `DEBUG`.

#### Scenario: Live passthrough on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the request is not banned for that error and continues to the pass path

#### Scenario: Live ban on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the client is forbidden (same as today's `BannedValue`)

#### Scenario: Clean client address and a failing header scope
- **WHEN** the client-address query returns no decision and one mapped header-scope query errors
- **THEN** the lookup reports a failure with a non-active remediation
- **AND** `crowdsecLapiFailureAction` decides the outcome
- **AND** no negative live-cache entry is written for that client address

#### Scenario: Clean client address and clean header scopes
- **WHEN** the client-address query and every mapped header-scope query return no decision
- **THEN** the lookup reports no remediation and no failure

#### Scenario: Header scope returns a ban
- **WHEN** the client-address query returns no decision and a mapped header-scope query returns a ban
- **THEN** that ban is the outcome

#### Scenario: Client-address query error still propagates
- **WHEN** the client-address query errors
- **THEN** the lookup reports that failure with a non-active remediation, unchanged from before this change

## ADDED Requirements

### Requirement: An active remediation outranks a header-scope failure
When a live (or none-mode) lookup has an active remediation and one of its header-scope queries also failed, the active remediation SHALL be the outcome. The failure MUST NOT downgrade it, mask it, or divert the request to `crowdsecLapiFailureAction`. The lookup SHALL keep returning an active remediation together with its existing non-nil "banned" signal, and SHALL return a non-active remediation together with a failure signal, so the caller can tell the two apart by the remediation kind alone.

#### Scenario: Active ban survives a failing header scope
- **WHEN** the client-address query returns an active ban and one mapped header-scope query errors
- **THEN** that ban is the outcome
- **AND** `crowdsecLapiFailureAction` is not consulted

#### Scenario: One scope errors and another returns a ban
- **WHEN** two header scopes are mapped, one query errors and the other returns a ban
- **THEN** that ban is the outcome
