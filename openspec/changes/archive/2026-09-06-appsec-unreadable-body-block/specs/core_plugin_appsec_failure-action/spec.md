## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500 or unreachable AppSec. An HTTP/2 or HTTP/3 body that cannot be buffered is not a failure verdict unless the operator sets `crowdsecAppsecUnreadableBodyBlock`.

## REMOVED Requirements

### Requirement: Unreadable body is headers-only AppSec GET
When the request is HTTP/2 or HTTP/3, has a body, and `ContentLength < 0`, `appsec.Client.Query` SHALL query AppSec with headers only (GET) and MUST NOT buffer or drop the original body. This SHALL apply for every `crowdsecAppsecFailureAction`, including default `ban`. Client IP SHALL be the `GetRemoteIP` value already passed into `Query`. `CrowdsecAppsecFailureAction` SHALL still apply to that GET if AppSec returns 500 or is unreachable.

#### Scenario: Unreadable POST under default ban still queries AppSec
- **WHEN** the request body cannot be buffered, the method has a body, and `crowdsecAppsecFailureAction` is `ban` (including omit)
- **THEN** AppSec is queried with headers only (GET)
- **AND** the original body is not dropped
- **AND** the client is not forbidden unless that AppSec call remediates or its failure action does

#### Scenario: Unreadable body passthrough still queries AppSec
- **WHEN** the request body cannot be buffered, the method has a body, and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** AppSec is queried with headers only (GET) and the original body is not dropped

### Requirement: Three AppSec block booleans are removed
`crowdsecAppsecFailureBlock`, `crowdsecAppsecUnreachableBlock`, and `crowdsecAppsecUnreadableBodyBlock` SHALL be removed from the plugin config struct. Operators who previously set those bools to `false` MUST set `crowdsecAppsecFailureAction: passthrough`.

#### Scenario: Old bool fields are gone
- **WHEN** plugin config is decoded
- **THEN** those three JSON keys are not fields on `Config` and do not change runtime behavior

## ADDED Requirements

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
