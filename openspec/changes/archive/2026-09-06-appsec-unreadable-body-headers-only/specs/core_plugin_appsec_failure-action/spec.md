## Purpose

Governs what this plugin does when AppSec does not return a usable verdict: listener HTTP 500 or unreachable AppSec. An HTTP/2 or HTTP/3 body that cannot be buffered is not a failure verdict; it is a headers-only AppSec query.

## REMOVED Requirements

### Requirement: One action covers 500, unreachable, and unreadable body
`CrowdsecAppsecFailureAction` SHALL apply to: AppSec HTTP 500; transport failure or HTTP 502/503/504; and an unreadable HTTP/2 or HTTP/3 body on a method that would have sent a body. `ban` SHALL drop the request. `passthrough` on 500 or unreachable SHALL continue as allow (then `next`). `passthrough` on unreadable body SHALL keep today’s headers-only GET to AppSec. `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`.

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

## ADDED Requirements

### Requirement: One action covers 500 and unreachable
`CrowdsecAppsecFailureAction` SHALL apply to AppSec HTTP 500 and to transport failure or HTTP 502/503/504. `ban` SHALL drop the request. `passthrough` SHALL continue as allow (then `next`). `captcha` SHALL use the configured captcha client (`pkg/captcha`), not AppSec JSON `action: captcha`. This action MUST NOT drop a request solely because the body cannot be buffered.

#### Scenario: Unreachable passthrough
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `passthrough`
- **THEN** the request proceeds to `next`

#### Scenario: Unreachable ban
- **WHEN** AppSec is unreachable and `crowdsecAppsecFailureAction` is `ban`
- **THEN** the client is forbidden with `ReasonAPPSEC`

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
