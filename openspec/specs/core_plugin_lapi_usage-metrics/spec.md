## Purpose

CrowdsecConnection reports remediation-component usage metrics to CrowdSec LAPI `POST /v1/usage-metrics` so `cscli metrics show bouncers` can slice this plugin like official bouncers.

## Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from the `net.IP` `pkg/ip.GetRemoteIP` already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). The request path MUST NOT parse `RemoteAddr` again and MUST NOT classify `ip_type` by parsing the client string (`ip.Family` on the string). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Drops with no CrowdSec decision SHALL send a plugin origin so they appear as `cscli metrics show bouncers` origin rows: `plugin:tech_getremotefail` when GetRemoteIP fails; `plugin:tech_trustipfail` when the trusted-IP checker fails; `plugin:tech_cachefail` when a cache error is fail-closed; `plugin:tech_streamfail` when stream is unhealthy; `plugin:lapi_failure` for live LAPI errors; `plugin:appsec_failure` for AppSec failure-action. Those paths MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, or `lists:`. Range-only cache hits with no stored origin MAY omit `origin`. The plugin MUST NOT send a `scenario` item label. The plugin MUST NOT send `labels.type=traefik_plugin`.

#### Scenario: List decision drop
- **WHEN** a request is banned by a decision whose origin is `lists` and scenario is `firehol_level1`
- **THEN** the next usage-metrics POST includes a `dropped` item with `origin=lists:firehol_level1`, `ip_type` of the client, and `remediation=ban`

#### Scenario: AppSec drop
- **WHEN** AppSec remediates the request
- **THEN** the `dropped` item has `origin=appsec`

#### Scenario: GetRemoteIP failure uses plugin origin
- **WHEN** the bouncer bans because GetRemoteIP failed
- **THEN** the `dropped` item has `origin=plugin:tech_getremotefail` and `ip_type` when the address is known

#### Scenario: Trusted-IP checker failure uses plugin origin
- **WHEN** the bouncer bans because the trusted-IP checker failed
- **THEN** the `dropped` item has `origin=plugin:tech_trustipfail`

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

### Requirement: Processed counts every handled request
Each request the bouncer handles (trusted-IP bypass, pass, and drop) SHALL increment `processed` with unit `request` and label `ip_type` only, classified from the `net.IP` GetRemoteIP already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). Disabled middleware MUST NOT increment. `processed` MUST NOT send `origin`. The request path MUST NOT classify `processed` `ip_type` by parsing the client string.

#### Scenario: Allowed request is processed
- **WHEN** a non-trusted client is allowed through
- **THEN** the next POST includes `processed` with that client's `ip_type`

### Requirement: Active decisions are a stream/alone gauge
In stream and alone modes, `active_decisions` SHALL be a gauge (unit `ip`) of decision records this connection currently applies (Ip, header-scope, and Range CIDRs), labeled `origin` (lists-rewritten) and `ip_type` of the decision value. Live, none, and AppSec-only modes SHALL omit `active_decisions`. The gauge MUST NOT expand a CIDR into host addresses.

#### Scenario: Stream IP ban is counted
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

### Requirement: Envelope identity
The remediation-component object SHALL send `version` from the plugin version, `type` `bouncer`, `name` `traefik_plugin`, `feature_flags` as an empty JSON array, and `utc_startup_timestamp` from connection start (MUST NOT be `time.Now()` at each push). User-Agent SHALL remain `Crowdsec-Bouncer-Traefik-Plugin/<version>`. `metrics` SHALL be a JSON array of windows.

#### Scenario: Startup timestamp is stable
- **WHEN** two usage-metrics POSTs occur from the same connection
- **THEN** both send the same `utc_startup_timestamp`
