## Purpose

Governs what this plugin does when CrowdSec LAPI does not return a usable verdict: live request errors, and stream/alone cache misses after the stream is marked unhealthy.

## ADDED Requirements

### Requirement: LapiFailureAction is the public LAPI fallback
Public config `lapiFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty or unknown values SHALL be rejected.

#### Scenario: Default is ban
- **WHEN** the operator omits `lapiFailureAction`
- **THEN** live LAPI errors and stream-unhealthy cache misses ban as today

#### Scenario: Captcha without provider is invalid
- **WHEN** `lapiFailureAction` is `captcha` and no captcha provider is set
- **THEN** plugin initialization fails validation

### Requirement: UpdateMaxFailure remains the stream unhealthy counter
`UpdateMaxFailure` SHALL keep today’s meaning: stream/alone poll failures increment a counter; when the counter reaches the configured maximum the stream is unhealthy; `-1` never marks unhealthy; default `0` marks unhealthy on the first failed poll. A later successful poll SHALL restore healthy. `LapiFailureAction` SHALL NOT replace this counter.

#### Scenario: Minus one never unhealthies
- **WHEN** `updateMaxFailure` is `-1` and stream polls fail
- **THEN** the stream stays healthy and cache-miss requests are allowed (then AppSec if enabled)

### Requirement: Live LAPI error uses LapiFailureAction
When a live (or none-mode) LAPI lookup fails, the plugin SHALL apply `lapiFailureAction`: `passthrough` proceeds to the pass path; `ban` remediates as a ban; `captcha` uses the configured captcha client. Cached hits SHALL still apply before a live lookup.

#### Scenario: Live passthrough on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `lapiFailureAction` is `passthrough`
- **THEN** the request is not banned for that error and continues to the pass path

#### Scenario: Live ban on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `lapiFailureAction` is `ban`
- **THEN** the client is forbidden (same as today’s `BannedValue`)

### Requirement: Stream unhealthy miss uses LapiFailureAction
When stream or alone mode is unhealthy, cache hits SHALL still apply. A cache miss SHALL apply `lapiFailureAction` instead of a hardcoded technical ban. `passthrough` SHALL use the existing pass path (AppSec still runs if enabled).

#### Scenario: Unhealthy miss passthrough
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `lapiFailureAction` is `passthrough`
- **THEN** the request continues to the pass path

#### Scenario: Unhealthy miss ban
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `lapiFailureAction` is `ban`
- **THEN** the client is forbidden with a technical remediation

#### Scenario: Unhealthy cache hit still remediates
- **WHEN** the stream is unhealthy and cache has an active ban for the client IP
- **THEN** that ban still applies regardless of `lapiFailureAction`

### Requirement: LapiFailureAction is on the connection identity
Routers that share one Crowdsec backend SHALL share `lapiFailureAction` (it is part of the reclaim identity with `UpdateMaxFailure`). Two routers MUST NOT disagree on LAPI fallback against one connection.

#### Scenario: Same LAPI action is shared
- **WHEN** two middlewares reclaim the same CrowdsecConnection
- **THEN** both use the same `lapiFailureAction`
