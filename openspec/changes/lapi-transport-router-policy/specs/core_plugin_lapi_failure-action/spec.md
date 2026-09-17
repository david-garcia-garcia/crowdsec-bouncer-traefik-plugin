## MODIFIED Requirements

### Requirement: Live LAPI error uses CrowdsecLapiFailureAction
When a live (or none-mode) LAPI lookup fails, the plugin SHALL apply the **calling bouncer’s** effective `crowdsecLapiFailureAction`: `passthrough` proceeds to the pass path; `ban` remediates as a ban; `captcha` uses the configured captcha client. Cached hits SHALL still apply before a live lookup.

#### Scenario: Live passthrough on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the request is not banned for that error and continues to the pass path

#### Scenario: Live ban on LAPI error
- **WHEN** `crowdsecMode` is `live`, LAPI returns an error, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the client is forbidden (same as today’s `BannedValue`)

### Requirement: Stream unhealthy miss uses CrowdsecLapiFailureAction
When stream or alone mode is unhealthy, cache hits SHALL still apply. A cache miss SHALL apply the **calling bouncer’s** effective `crowdsecLapiFailureAction` instead of a hardcoded technical ban. `passthrough` SHALL use the existing pass path (AppSec still runs if enabled).

#### Scenario: Unhealthy miss passthrough
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the request continues to the pass path

#### Scenario: Unhealthy miss ban
- **WHEN** the stream is unhealthy, the client IP is not in cache, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the client is forbidden with a technical remediation

#### Scenario: Unhealthy cache hit still remediates
- **WHEN** the stream is unhealthy and cache has an active ban for the client IP
- **THEN** that ban still applies regardless of `crowdsecLapiFailureAction`

## REMOVED Requirements

### Requirement: CrowdsecLapiFailureAction is on the connection identity
**Reason**: Per-router policy must not force a new stream cursor incarnation or be silently ignored on live joiners.
**Migration**: Operators keep setting `crowdsecLapiFailureAction` on each middleware; each bouncer applies its own effective action while sharing one `lapi.Client` when the session matches.

## ADDED Requirements

### Requirement: CrowdsecLapiFailureAction is per-router on Bouncer
Each middleware `New` SHALL resolve `crowdsecLapiFailureAction` through the same effective-action helper used for AppSec failure action and SHALL apply that value on live errors and stream-unhealthy cache misses for that bouncer only. Two bouncers sharing one `lapi.Client` MAY use different effective LAPI failure actions.

#### Scenario: Two routers different LAPI failure action
- **WHEN** two live stream middlewares share one LAPI URL and key and differ only on `crowdsecLapiFailureAction`
- **THEN** both use the same `lapi.Client` incarnation
- **AND** an unhealthy cache miss on the first middleware follows the first middleware’s action
- **AND** an unhealthy cache miss on the second middleware follows the second middleware’s action

### Requirement: Redis unreachable fail-closed is per-router on Bouncer
Each middleware SHALL read `crowdsecRedisCacheUnreachableBlock` into its bouncer and SHALL apply that boolean when the decision cache is unreachable for that bouncer’s requests. It MUST NOT be part of the LAPI reclaim settings hash.

#### Scenario: Two routers different Redis fail-closed
- **WHEN** two stream middlewares share one LAPI connection and differ only on `crowdsecRedisCacheUnreachableBlock`
- **THEN** both share the same cache client
- **AND** each bouncer applies its own fail-closed policy on cache unreachable
