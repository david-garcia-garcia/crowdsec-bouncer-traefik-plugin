## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500 or unreachable AppSec. An HTTP/2 or HTTP/3 body that cannot be buffered is not a failure verdict unless the operator sets `crowdsecAppsecUnreadableBodyBlock`.

## Requirements

### Requirement: CrowdsecAppsecFailureAction is the public AppSec fallback
Public config `crowdsecAppsecFailureAction` SHALL be one of `passthrough`, `ban`, or `captcha`. The default SHALL be `ban`. `captcha` SHALL be rejected at ValidateParams unless a captcha provider is configured. Empty SHALL be treated as `ban` (same as omit). Unknown values SHALL be rejected. This key SHALL be per-router (not on `lapi.Client` identity) so two routes can disagree on AppSec fallback against one LAPI.

#### Scenario: Default is ban
- **WHEN** the operator omits `crowdsecAppsecFailureAction` and AppSec returns HTTP 500
- **THEN** the client is forbidden (same as today’s `crowdsecAppsecFailureBlock` default true)

#### Scenario: Two routers may differ
- **WHEN** two middlewares share one `lapi.Client` and set different `crowdsecAppsecFailureAction` values
- **THEN** each route applies its own AppSec fallback

### Requirement: One action covers 500 and unreachable
`CrowdsecAppsecFailureAction` SHALL apply to AppSec HTTP 500 and to transport failure or HTTP 502/503/504. `ban` SHALL drop the request. `passthrough` SHALL continue as allow (then `next`). `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. This action MUST NOT drop a request solely because the body cannot be buffered. HTTP 502, 503, and 504 from the AppSec listener SHALL be unreachable (same fallback as a transport failure), not a generic non-200 ban.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 passthrough
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next` (same as transport unreachable)

#### Scenario: Reverse-proxy HTTP 502, 503, or 504 ban
- **WHEN** the AppSec listener returns HTTP 502, 503, or 504 and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

### Requirement: Unreadable body is headers-only AppSec GET unless CrowdsecAppsecUnreadableBodyBlock
When the request is HTTP/2 or HTTP/3, has a body, and `ContentLength < 0`, and `crowdsecAppsecUnreadableBodyBlock` is false (including omit / `New()` default), `appsec.Client.Query` SHALL query AppSec with headers only (GET) and MUST NOT buffer or drop the original body. This SHALL apply for every `crowdsecAppsecFailureAction`, including default `ban`. Client IP SHALL be the `GetRemoteIP` value already passed into `Query`. `CrowdsecAppsecFailureAction` SHALL still apply to that GET if AppSec returns 500 or is unreachable.

#### Scenario: Unreadable POST under default ban still queries AppSec
- **WHEN** the request body cannot be buffered, the method has a body, `crowdsecAppsecUnreadableBodyBlock` is false (including omit), and `crowdsecAppsecFailureAction` is `ban` (including omit)
- **THEN** AppSec is queried with headers only (GET)
- **AND** the original body is not dropped
- **AND** the client is not forbidden unless that AppSec call remediates or its failure action does

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method has a body, `crowdsecAppsecUnreadableBodyBlock` is false, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

### Requirement: CrowdsecAppsecUnreadableBodyBlock drops unreadable methods with a body
Public config `crowdsecAppsecUnreadableBodyBlock` SHALL be a per-router bool on `Config` (JSON `crowdsecAppsecUnreadableBodyBlock`). Default SHALL be false. When true, and the request is HTTP/2 or HTTP/3 with a body and `ContentLength < 0`, and the method is POST, PUT, PATCH, or DELETE, `appsec.Client.Query` SHALL return error `appsecQuery:unreadableBody dropped` without calling AppSec. GET and HEAD SHALL still send a headers-only GET. This SHALL apply even when `crowdsecAppsecFailureAction` is `passthrough`. `crowdsecAppsecFailureBlock` and `crowdsecAppsecUnreachableBlock` SHALL remain absent from `Config`.

#### Scenario: Unreadable POST is dropped when the bool is true
- **WHEN** the request body cannot be buffered, the method has a body, and `crowdsecAppsecUnreadableBodyBlock` is true
- **THEN** AppSec is not called
- **AND** Query returns `appsecQuery:unreadableBody dropped`

#### Scenario: Unreadable GET is not dropped when the bool is true
- **WHEN** the request is GET, HTTP/3, `ContentLength < 0`, and `crowdsecAppsecUnreadableBodyBlock` is true
- **THEN** AppSec is queried with headers only (GET)

#### Scenario: Passthrough does not override the bool
- **WHEN** `crowdsecAppsecUnreadableBodyBlock` is true, `crowdsecAppsecFailureAction` is `passthrough`, and the request is an unreadable POST
- **THEN** AppSec is not called
- **AND** Query returns `appsecQuery:unreadableBody dropped`

### Requirement: Structured AppSec verdicts are not failure actions
HTTP 200 and parseable AppSec JSON `action` values (`allow`, `ban`, `challenge`, AppSec `captcha` HTML) SHALL keep existing bot-detection behavior. `CrowdsecAppsecFailureAction` MUST NOT rewrite those envelopes. Legacy empty/non-JSON non-200 (other than 500/502/503/504) SHALL still ban.

#### Scenario: Challenge still relays
- **WHEN** AppSec returns HTTP 403 with `action` `challenge` and a non-empty body
- **THEN** the bouncer relays that envelope regardless of `crowdsecAppsecFailureAction`
