## Purpose

Live and none-mode LAPI lookups skip outbound CrowdSec HTTP while the reclaimed LAPI Tracker’s backoff is active, then apply the existing LAPI failure action without waiting on timeout.

## Requirements

### Requirement: Live LAPI skip uses the Tracker then CrowdsecLapiFailureAction
When `crowdsecMode` is `live` or `none` and the LAPI Tracker is unhealthy, the plugin SHALL NOT call LAPI HTTP for that request. It SHALL apply `crowdsecLapiFailureAction` (`passthrough` | `ban` | `captcha`) the same way as a live LAPI error today. Cached hits in live mode SHALL still apply before a live lookup. Stream and alone request paths SHALL NOT use this Tracker (`updateMaxFailure` / `StreamHealthy` stay as today).

#### Scenario: Unhealthy live passthrough skips HTTP
- **WHEN** `crowdsecMode` is `live`, the LAPI Tracker is unhealthy, and `crowdsecLapiFailureAction` is `passthrough`
- **THEN** the plugin does not wait on `HTTPTimeoutSeconds` for LAPI
- **AND** the request continues to the pass path

#### Scenario: Unhealthy live ban skips HTTP
- **WHEN** `crowdsecMode` is `live`, the LAPI Tracker is unhealthy, and `crowdsecLapiFailureAction` is `ban`
- **THEN** the plugin does not call LAPI HTTP
- **AND** the client is forbidden

#### Scenario: Stream poll is not this Tracker
- **WHEN** `crowdsecMode` is `stream` and stream polls fail
- **THEN** `updateMaxFailure` still marks the stream unhealthy
- **AND** the LAPI request-path Tracker is not used for those polls

### Requirement: Live query errors increment the LAPI Tracker
Transport, reverse-proxy, non-2xx, and live JSON/duration parse errors on live/none LAPI queries (including header-scope queries) SHALL record a failure. A live decision that remediates (ban/captcha) SHALL NOT record a failure. `handleNoStreamCache:banned` is not a Tracker failure.

#### Scenario: Unreachable live lookup records a failure
- **WHEN** a live `ip=` LAPI query is unreachable
- **THEN** the LAPI Tracker records a failure
- **AND** `crowdsecLapiFailureAction` still applies for that request

#### Scenario: Banned decision does not record a failure
- **WHEN** live LAPI returns an active ban for the client IP
- **THEN** the LAPI Tracker does not record a failure
- **AND** that ban still remediates

### Requirement: LAPI backoff knobs are public and on live identity
Public config `lapiFailureBackoffTimeout`, `lapiFailureBackoffBucketWindow`, and `lapiFailureBackoffBucketThreshold` SHALL default to 30, 30, and 5. Threshold SHALL be at least -1. Timeout and window SHALL be at least 0. These three fields SHALL be part of live/none LAPI reclaim identity (with `HTTPTimeoutSeconds` and `crowdsecLapiFailureAction`). They MUST NOT be in the stream session prefix. Two routers MUST NOT share one `lapi.Client` with disagreeing LAPI backoff knobs.

#### Scenario: Default knobs
- **WHEN** the operator omits the three LAPI backoff keys
- **THEN** timeout is 30 seconds, window is 30 seconds, and threshold is 5

#### Scenario: Same live identity shares one Tracker
- **WHEN** two live middlewares reclaim the same `lapi.Client`
- **THEN** both share one LAPI Tracker
