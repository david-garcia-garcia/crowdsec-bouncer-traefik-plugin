## MODIFIED Requirements

### Requirement: Live LAPI error uses CrowdsecLapiFailureAction
When a live (or none-mode) LAPI lookup fails, the plugin SHALL apply `crowdsecLapiFailureAction`: `passthrough` proceeds to the pass path; `ban` remediates as a ban; `captcha` uses the configured captcha client. Cached hits SHALL still apply before a live lookup. Header-scope LAPI query failures during live lookup SHALL count as LAPI lookup failures with the same failure-action semantics as IP query unreachable errors.

#### Scenario: Live passthrough on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the request is not banned for that error and continues to the pass path

#### Scenario: Live ban on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the client is forbidden (same as today’s `BannedValue`)

#### Scenario: Live ban on header-scope LAPI error
- **WHEN** `crowdsecMode` is `live`, the IP query succeeds or is allowed, a mapped header-scope LAPI query fails, and `crowdsecLapiFailureAction` is `ban`
- **THEN** `LiveLookup` returns an error
- **AND** the bouncer applies ban remediation for that LAPI failure

#### Scenario: Active IP remediation when scope query fails
- **WHEN** the IP query already yields active ban remediation and a header-scope LAPI query fails
- **THEN** `LiveLookup` returns an error
- **AND** existing bouncer behavior still remediates from the active IP ban kind when applicable
