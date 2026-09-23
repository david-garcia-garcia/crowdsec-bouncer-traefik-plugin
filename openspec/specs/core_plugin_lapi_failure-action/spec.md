## Purpose

Governs what this plugin does when CrowdSec LAPI does not return a usable verdict: live request errors, and stream/alone cache misses after the stream is marked unhealthy.

## Requirements

### Requirement: CrowdsecLapiFailureAction is the public LAPI fallback
Public config `bouncerLapiFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless this router has a non-empty captcha instance name after owner-fill rules (`captchaEnabled` and empty name fills to the Traefik name). Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. On `Bouncer` the field SHALL stay `lapiFailureAction`. A captcha verdict without a subscribed published client SHALL still ban at runtime.

#### Scenario: Default is ban
- **WHEN** the operator omits `bouncerLapiFailureAction`
- **THEN** live LAPI errors and stream-unhealthy cache misses ban as today

#### Scenario: Captcha without instance name is invalid
- **WHEN** `bouncerLapiFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** plugin initialization fails validation

#### Scenario: Owner omit is a legal captcha action
- **WHEN** `captchaEnabled` is true, `captchaInstanceName` is omitted, and `bouncerLapiFailureAction` is `captcha`
- **THEN** `ValidateParams` accepts the action
- **AND** the filled name is this middleware's Traefik name

### Requirement: UpdateMaxFailure remains the stream unhealthy counter
`LapiUpdateMaxFailure` SHALL keep today’s meaning: stream/alone poll failures increment a counter; when the counter reaches the configured maximum the stream is unhealthy; `-1` never marks unhealthy; default `0` marks unhealthy on the first failed poll. A later successful poll SHALL restore healthy. `bouncerLapiFailureAction` SHALL NOT replace this counter.

#### Scenario: Minus one never unhealthies
- **WHEN** `lapiUpdateMaxFailure` is `-1` and stream polls fail
- **THEN** the stream stays healthy and cache-miss requests are allowed (then AppSec if enabled)

### Requirement: Live LAPI error uses CrowdsecLapiFailureAction
When a live (or none-mode) LAPI lookup fails, the plugin SHALL apply `bouncerLapiFailureAction`: `passthrough` proceeds to the pass path; `ban` remediates as a ban; `captcha` uses the configured captcha client. Cached hits SHALL still apply before a live lookup. A failure of **any** query the lookup makes counts as a failed lookup: the client-address query and every mapped header-scope query alike. A header-scope query that errors MUST NOT be reported as "no decision on that scope". The lookup SHALL report it to the caller with a **non-active** remediation, exactly as a failed client-address query is reported, so the configured action decides. When a header-scope query fails, the lookup MUST NOT write a negative live-cache entry for that client address, so the unverified allow does not survive in cache. The failure SHALL be logged at a level an operator sees at the plugin's default log level, not at `DEBUG`.

#### Scenario: Live passthrough on LAPI error
- **WHEN** `lapiMode` is `live`, LAPI returns an error, and `bouncerLapiFailureAction` is `passthrough`
- **THEN** the request is not banned for that error and continues to the pass path

#### Scenario: Live ban on LAPI error
- **WHEN** `lapiMode` is `live`, LAPI returns an error, and `bouncerLapiFailureAction` is `ban`
- **THEN** the client is forbidden (same as today's `BannedValue`)

#### Scenario: Clean client address and a failing header scope
- **WHEN** the client-address query returns no decision and one mapped header-scope query errors
- **THEN** the lookup reports a failure with a non-active remediation
- **AND** `bouncerLapiFailureAction` decides the outcome
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

### Requirement: An active remediation outranks a header-scope failure
When a live (or none-mode) lookup has an active remediation and one of its header-scope queries also failed, the active remediation SHALL be the outcome. The failure MUST NOT downgrade it, mask it, or divert the request to `bouncerLapiFailureAction`. The lookup SHALL keep returning an active remediation together with its existing non-nil "banned" signal, and SHALL return a non-active remediation together with a failure signal, so the caller can tell the two apart by the remediation kind alone.

#### Scenario: Active ban survives a failing header scope
- **WHEN** the client-address query returns an active ban and one mapped header-scope query errors
- **THEN** that ban is the outcome
- **AND** `bouncerLapiFailureAction` is not consulted

#### Scenario: One scope errors and another returns a ban
- **WHEN** two header scopes are mapped, one query errors and the other returns a ban
- **THEN** that ban is the outcome

### Requirement: Stream unhealthy miss uses CrowdsecLapiFailureAction
When stream or alone mode is unhealthy, cache hits SHALL still apply. A cache miss SHALL apply `bouncerLapiFailureAction` instead of a hardcoded technical ban. `passthrough` SHALL use the existing pass path (AppSec still runs if enabled).

#### Scenario: Unhealthy miss passthrough
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `bouncerLapiFailureAction` is `passthrough`
- **THEN** the request continues to the pass path

#### Scenario: Unhealthy miss ban
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `bouncerLapiFailureAction` is `ban`
- **THEN** the client is forbidden with a technical remediation

#### Scenario: Unhealthy cache hit still remediates
- **WHEN** the stream is unhealthy and cache has an active ban for the client IP
- **THEN** that ban still applies regardless of `bouncerLapiFailureAction`

### Requirement: CrowdsecLapiFailureAction is per-router on Bouncer
Routers that share one LAPI Client SHALL each apply their own `bouncerLapiFailureAction`. The action MUST NOT be part of LAPI reclaim identity. Two routers MAY disagree on LAPI fallback against one `lapi.Client`. The Client MUST NOT expose a failure-action accessor.

#### Scenario: Two routers disagree on LAPI action
- **WHEN** two middlewares reclaim the same `lapi.Client` and set different `bouncerLapiFailureAction` values
- **THEN** each router applies its own action on a live LAPI error or stream-unhealthy cache miss

#### Scenario: Failure action is not on Client identity
- **WHEN** two live `New` calls share LAPI URL and key and differ only on `bouncerLapiFailureAction`
- **THEN** they reclaim the same Client
- **AND** the Client has no failure-action getter
