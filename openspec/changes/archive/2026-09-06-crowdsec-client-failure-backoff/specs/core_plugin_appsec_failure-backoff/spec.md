## Purpose

AppSec queries skip outbound listener HTTP while the reclaimed AppSec Tracker’s backoff is active, then apply the existing AppSec failure action without waiting on timeout.

## ADDED Requirements

### Requirement: AppSec skip uses the Tracker then CrowdsecAppsecFailureAction
When AppSec is enabled and the AppSec Tracker is unhealthy, `Query` SHALL NOT call AppSec HTTP. It SHALL apply `crowdsecAppsecFailureAction` the same way as unreachable AppSec today (`passthrough` | `ban` | `captcha`). This skip SHALL apply on the pass path in every mode, including stream. Structured AppSec envelopes are not this requirement.

#### Scenario: Unhealthy AppSec passthrough skips HTTP
- **WHEN** AppSec is enabled, the AppSec Tracker is unhealthy, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the plugin does not wait on `HTTPTimeoutSeconds` for AppSec
- **AND** the request proceeds to `next`

#### Scenario: Unhealthy AppSec ban skips HTTP
- **WHEN** AppSec is enabled, the AppSec Tracker is unhealthy, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the plugin does not call AppSec HTTP
- **AND** the client is forbidden with `ReasonAPPSEC`

### Requirement: Unreachable and 500 increment the AppSec Tracker
Transport failure, HTTP 502/503/504, and HTTP 500 SHALL record a failure. An unreadable HTTP/2 or HTTP/3 body SHALL NOT record a failure. Structured AppSec JSON actions (`allow`, `ban`, `challenge`, AppSec `captcha` HTML) SHALL NOT record a failure.

#### Scenario: Unreachable records a failure
- **WHEN** AppSec `Do` fails or returns 502/503/504
- **THEN** the AppSec Tracker records a failure
- **AND** `crowdsecAppsecFailureAction` still applies for that request

#### Scenario: Unreadable body does not record a failure
- **WHEN** the request body cannot be buffered on a method that would send a body
- **THEN** the AppSec Tracker does not record a failure
- **AND** `crowdsecAppsecFailureAction` still applies as today

### Requirement: AppSec backoff knobs are public and on AppSec identity
Public config `appsecFailureBackoffTimeout`, `appsecFailureBackoffBucketWindow`, and `appsecFailureBackoffBucketThreshold` SHALL default to 30, 30, and 5. Threshold SHALL be at least -1. Timeout and window SHALL be at least 0. These three fields SHALL be part of AppSec reclaim identity. `crowdsecAppsecFailureAction` SHALL remain per-router on the Bouncer.

#### Scenario: Default knobs
- **WHEN** the operator omits the three AppSec backoff keys
- **THEN** timeout is 30 seconds, window is 30 seconds, and threshold is 5

#### Scenario: Same AppSec identity shares one Tracker
- **WHEN** two middlewares reclaim the same `appsec.Client`
- **THEN** both share one AppSec Tracker
