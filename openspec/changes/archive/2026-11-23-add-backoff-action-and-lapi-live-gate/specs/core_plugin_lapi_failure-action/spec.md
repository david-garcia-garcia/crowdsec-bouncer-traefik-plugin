## ADDED Requirements

### Requirement: Live LAPI gate skip uses bouncerLapiBackOffAction
When a live or none-mode lookup returns `lapi.ErrGateSkip`, the router SHALL apply its own `bouncerLapiBackOffAction` and MUST NOT apply `bouncerLapiFailureAction`. Values SHALL be `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`, and empty SHALL mean `ban`. The action SHALL be per-router on `Bouncer` and MUST NOT be part of LAPI reclaim identity. The Client MUST NOT expose a backoff-action accessor.

#### Scenario: Default backoff action bans
- **WHEN** the LAPI gate is backing off and the router omits `bouncerLapiBackOffAction`
- **THEN** the client is forbidden
- **AND** no GET is sent to LAPI

#### Scenario: Passthrough backoff action continues
- **WHEN** the LAPI gate is backing off and `bouncerLapiBackOffAction` is `passthrough`
- **THEN** the request continues to the pass path (the rate limit, AppSec, and ModSec still run if subscribed)

#### Scenario: Captcha backoff action serves the router's captcha
- **WHEN** the LAPI gate is backing off, `bouncerLapiBackOffAction` is `captcha`, and the router has a usable captcha client
- **THEN** the router's captcha challenge is served

#### Scenario: Failure action does not decide a skip
- **WHEN** the LAPI gate is backing off, `bouncerLapiFailureAction` is `passthrough`, and `bouncerLapiBackOffAction` is `ban`
- **THEN** the client is forbidden

#### Scenario: Two routers disagree on the backoff action
- **WHEN** two routers use the same live LAPI Client and set different `bouncerLapiBackOffAction` values
- **AND** the shared gate is backing off
- **THEN** each router applies its own backoff action

#### Scenario: Backoff action is not on Client identity
- **WHEN** two live `New` calls share middleware name, LAPI URL, and key and differ only on `bouncerLapiBackOffAction`
- **THEN** they reclaim the same Client

### Requirement: A LAPI backoff answer is labelled as backoff
A LAPI backoff `ban` or `captcha` SHALL set the remediation header reason `lapi-backoff` (`ban:lapi-backoff`, `captcha:lapi-backoff`) and SHALL count the drop under usage-metrics origin `plugin:lapi_failure`. A `ban` SHALL use RemediationReason `LAPI`. A backoff `passthrough` SHALL set no remediation header and SHALL record no drop.

#### Scenario: Backoff ban header and origin
- **WHEN** `bouncerRemediationHeadersCustomName` is set and the LAPI gate skip answers `ban`
- **THEN** the header value is `ban:lapi-backoff`
- **AND** the dropped request counts under origin `plugin:lapi_failure`

#### Scenario: Real failure keeps its own reason
- **WHEN** the LAPI gate admits the GET and LAPI times out with `bouncerLapiFailureAction` `ban`
- **THEN** the header value is `ban:lapi-failure`
