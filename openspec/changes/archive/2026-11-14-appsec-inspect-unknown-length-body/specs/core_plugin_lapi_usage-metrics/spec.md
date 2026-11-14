## MODIFIED Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from the `net.IP` `pkg/ip.GetRemoteIP` already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). The request path MUST NOT parse `RemoteAddr` again and MUST NOT classify `ip_type` by parsing the client string (`ip.Family` on the string). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Drops with no CrowdSec decision SHALL send a plugin origin so they appear as `cscli metrics show bouncers` origin rows: `plugin:tech_cachefail` when a cache error is fail-closed; `plugin:tech_streamfail` when stream is unhealthy; `plugin:lapi_failure` for live LAPI errors; `plugin:appsec_failure` for AppSec failure-action; `plugin:appsec_body_timeout` when the AppSec body read timeout blocks a request (`core_plugin_appsec_body-read-timeout`). Those paths MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, or `lists:`. Range-only cache hits SHALL send `origin` from the winning Range CIDR’s stored suffix when that suffix is present. A letter-only `range-index` line MAY omit `origin`. The plugin MUST NOT send a `scenario` item label, including when the DecisionStore has interned the raw LAPI scenario. The plugin MUST NOT send `labels.type=traefik_plugin`.

#### Scenario: List decision drop
- **WHEN** a request is banned by a decision whose origin is `lists` and scenario is `firehol_level1`
- **THEN** the next usage-metrics POST includes a `dropped` item with `origin=lists:firehol_level1`, `ip_type` of the client, and `remediation=ban`

#### Scenario: Range-only stream drop uses stored origin
- **WHEN** stream has a Range ban whose origin is `crowdsec` and the client IP is inside that CIDR with no Ip or header hit
- **THEN** the `dropped` item has `origin=crowdsec` and `remediation=ban`

#### Scenario: Letter-only Range line omits origin
- **WHEN** `range-index` holds only `cidr=t` for a containing ban and the client IP has no Ip or header hit
- **THEN** the request is still banned and the `dropped` item MAY omit `origin`

#### Scenario: AppSec drop
- **WHEN** AppSec remediates the request
- **THEN** the `dropped` item has `origin=appsec`

#### Scenario: GetRemoteIP error is not a drop
- **WHEN** `GetRemoteIP` returns an error
- **THEN** the response status is 502
- **AND** no `dropped` item is recorded for that request

#### Scenario: Cache fail-closed uses plugin origin
- **WHEN** the bouncer bans because a cache error is fail-closed
- **THEN** the `dropped` item has `origin=plugin:tech_cachefail`

#### Scenario: Stream unhealthy uses plugin origin
- **WHEN** stream is unhealthy and the failure action bans
- **THEN** the `dropped` item has `origin=plugin:tech_streamfail`

#### Scenario: Live LAPI failure uses plugin origin
- **WHEN** live lookup fails and the failure action bans
- **THEN** the `dropped` item has `origin=plugin:lapi_failure`

#### Scenario: AppSec failure-action uses plugin origin
- **WHEN** AppSec is unreachable and the failure action bans
- **THEN** the `dropped` item has `origin=plugin:appsec_failure`

#### Scenario: Interned scenario is not a label
- **WHEN** stream has interned a raw LAPI scenario on an Ip ban and that ban drops a request
- **THEN** the `dropped` item has no `scenario` label
- **AND** `origin` is still the folded metrics origin

#### Scenario: AppSec body read timeout uses its own plugin origin
- **WHEN** the bouncer bans because the AppSec body read timeout expired
- **THEN** the `dropped` item has `origin=plugin:appsec_body_timeout` and `remediation=ban`
- **AND** it is not `plugin:appsec_failure`
