## ADDED Requirements

### Requirement: bouncerAppsecFailureAction is the public AppSec fallback
Public config `bouncerAppsecFailureAction` SHALL be `passthrough`, `ban`, or `captcha`. The default SHALL be `passthrough`, and empty SHALL mean `passthrough`; that resolution is AppSec's own (LAPI's empty stays `ban`). `captcha` SHALL fail ValidateParams unless the router has a captcha instance name after owner-fill. Unknown values SHALL fail. The key SHALL be per-router, not on any Client identity. On `Bouncer` the field SHALL stay `appsecFailureAction`.

#### Scenario: Default is passthrough
- **WHEN** the operator omits `bouncerAppsecFailureAction` and AppSec returns HTTP 500
- **AND** the URL path is not under `/crowdsec-internal/challenge/`
- **THEN** the request proceeds to `next`

#### Scenario: Empty AppSec action is not the LAPI default
- **WHEN** a router sets `bouncerAppsecFailureAction` and `bouncerLapiFailureAction` to empty strings
- **THEN** an AppSec HTTP 500 on that router proceeds to `next`
- **AND** a failed live LAPI lookup on that router is banned

#### Scenario: Default streams an unknown-length body as headers only
- **WHEN** the operator omits `bouncerAppsecFailureAction`
- **AND** a POST, PUT, or PATCH body arrives with no length and cannot be buffered
- **THEN** AppSec is queried with headers only (GET) and the request is not dropped

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `bouncerAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

#### Scenario: Captcha without instance name is invalid
- **WHEN** `bouncerAppsecFailureAction` is `captcha` and `captchaInstanceName` is empty after owner-fill rules
- **THEN** plugin initialization fails validation

### Requirement: AppSec gate skip uses bouncerAppsecBackOffAction
When the AppSec gate denies Allow, AppSec SHALL NOT be called and `bouncerAppsecFailureAction` SHALL NOT decide. The router SHALL apply its own `bouncerAppsecBackOffAction`: `passthrough` (default; empty means `passthrough`) continues, then ModSec if subscribed; `ban` writes the ban template with RemediationReason `APPSEC`; `captcha` serves the router's captcha gate. `ban` and `captcha` SHALL use header reason `appsec-backoff` and origin `plugin:appsec_failure`.

#### Scenario: After trip, default skip passes even when FailureAction is ban
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecFailureAction` is `ban` and `bouncerAppsecBackOffAction` is omitted
- **THEN** the client is not forbidden for that skip
- **AND** AppSec is not called

#### Scenario: Backoff action ban forbids the skip
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecBackOffAction` is `ban`
- **THEN** the client is forbidden with RemediationReason `APPSEC` and header `ban:appsec-backoff`
- **AND** AppSec is not called

#### Scenario: Backoff action captcha serves the router's captcha
- **WHEN** the AppSec Gate denies Allow
- **AND** `bouncerAppsecBackOffAction` is `captcha` and the router has a usable captcha client
- **THEN** the router's captcha challenge is served with header `captcha:appsec-backoff`

### Requirement: The AppSec failure action still covers admitted misses
FailureAction SHALL still apply to an admitted miss (HTTP 500, unreachable, response-body io error), to an admission error other than inbound cancel (for example a gate closed on reclaim), and to an unreadable body while the gate is not backing off. While the gate is backing off, an unreadable body SHALL be a skip like any other request and SHALL get `bouncerAppsecBackOffAction`.

#### Scenario: Admitted 500 uses the failure action
- **WHEN** the Gate admits the request
- **AND** AppSec returns HTTP 500
- **AND** `bouncerAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with header `ban:appsec-failure`

#### Scenario: Unreadable body while backing off uses the backoff action
- **WHEN** the AppSec Gate is backing off
- **AND** a POST body without a length cannot be buffered and `bouncerAppsecFailureAction` is `ban`
- **AND** `bouncerAppsecBackOffAction` is `ban`
- **THEN** the client is forbidden with header `ban:appsec-backoff`

#### Scenario: Unreadable body while healthy uses the failure action
- **WHEN** the AppSec Gate is not backing off
- **AND** a POST body without a length cannot be buffered and `bouncerAppsecFailureAction` is `ban`
- **THEN** the request is dropped with header `ban:appsec-failure`

## REMOVED Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
**Reason**: The default moves from `ban` to `passthrough`, and an empty value now means `passthrough` for AppSec. The header also used the old `crowdsec*` key name.
**Migration**: "bouncerAppsecFailureAction is the public AppSec fallback" carries the same rules with the new default. Operators who relied on the omitted default `ban` set `bouncerAppsecFailureAction: ban`.

### Requirement: Unhealthy skip is not a failure action
**Reason**: A gate skip no longer always continues. It answers with the per-router `bouncerAppsecBackOffAction`, and the default FailureAction is now `passthrough`.
**Migration**: "AppSec gate skip uses bouncerAppsecBackOffAction" sets the skip answer (default `passthrough` keeps the old behaviour). "The AppSec failure action still covers admitted misses" keeps the rest. Operators who want a skip to ban set `bouncerAppsecBackOffAction: ban`.
