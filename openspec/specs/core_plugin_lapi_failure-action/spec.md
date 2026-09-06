## Purpose

Governs what this plugin does when CrowdSec LAPI does not return a usable verdict: live request errors, and stream/alone cache misses after the stream is marked unhealthy.

## Requirements

### Requirement: CrowdsecLapiFailureAction is the public LAPI fallback
Public config `crowdsecLapiFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected.

#### Scenario: Default is ban
- **WHEN** the operator omits `crowdsecLapiFailureAction`
- **THEN** live LAPI errors and stream-unhealthy cache misses ban as today

#### Scenario: Captcha without provider is invalid
- **WHEN** `crowdsecLapiFailureAction` is `captcha` and no captcha provider is set
- **THEN** plugin initialization fails validation

### Requirement: UpdateMaxFailure remains the stream unhealthy counter
`UpdateMaxFailure` SHALL keep today’s meaning: stream/alone poll failures increment a counter; when the counter reaches the configured maximum the stream is unhealthy; `-1` never marks unhealthy; default `0` marks unhealthy on the first failed poll. A later successful poll SHALL restore healthy. `CrowdsecLapiFailureAction` SHALL NOT replace this counter.

#### Scenario: Minus one never unhealthies
- **WHEN** `updateMaxFailure` is `-1` and stream polls fail
- **THEN** the stream stays healthy and cache-miss requests are allowed (then AppSec if enabled)

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

### Requirement: Stream unhealthy miss uses CrowdsecLapiFailureAction
When stream or alone mode is unhealthy, cache hits SHALL still apply. A cache miss SHALL apply `crowdsecLapiFailureAction` instead of a hardcoded technical ban. `passthrough` SHALL use the existing pass path (AppSec still runs if enabled).

#### Scenario: Unhealthy miss passthrough
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the request continues to the pass path

#### Scenario: Unhealthy miss ban
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the client is forbidden with a technical remediation

#### Scenario: Unhealthy cache hit still remediates
- **WHEN** the stream is unhealthy and cache has an active ban for the client IP
- **THEN** that ban still applies regardless of `crowdsecLapiFailureAction`

### Requirement: CrowdsecLapiFailureAction is on the connection identity
Routers that share one LAPI backend SHALL share `crowdsecLapiFailureAction` (it is part of the LAPI reclaim identity with `UpdateMaxFailure`). Two routers MUST NOT disagree on LAPI fallback against one `lapi.Client`.

#### Scenario: Same LAPI action is shared
- **WHEN** two middlewares reclaim the same `lapi.Client`
- **THEN** both use the same `crowdsecLapiFailureAction`
