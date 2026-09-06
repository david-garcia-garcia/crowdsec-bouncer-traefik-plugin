## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500, unreachable AppSec, or a request body that cannot be buffered for inspection.

## Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `crowdsecAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI.

#### Scenario: Default is ban
- **WHEN** the operator omits `crowdsecAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `crowdsecAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; an unreadable HTTP/2 or HTTP/3 body on a method that would have sent a body; and failure to read or cap the AppSec response body before parse. `ban` SHALL drop the request. `passthrough` on 500 or unreachable SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method has a body, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

#### Scenario: Unreadable body ban
- **WHEN** the request body cannot be buffered, the method has a body, and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the request is dropped without calling origin

#### Scenario: Response read error passthrough
- **WHEN** reading the AppSec response body fails and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds as allow

#### Scenario: Response read error ban
- **WHEN** reading the AppSec response body fails and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML) SHALL keep existing bot-detection behavior. `CrowdsecAppsecFailureAction` MUST NOT rewrite those envelopes. Legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban.

#### Scenario: Challenge still relays
- **WHEN** AppSec returns HTTP 403 with `action` `challenge` and a non-empty body
- **THEN** the bouncer relays that envelope regardless of `crowdsecAppsecFailureAction`

### Requirement: Three AppSec block booleans are removed
`crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL be removed from the plugin config struct. Operators who previously set those bools to `false` MUST set `crowdsecAppsecFailureAction: passthrough`.

#### Scenario: Old bool fields are gone
- **WHEN** plugin config is decoded
- **THEN** those three JSON keys are not fields on `Config` and do not change runtime behavior
