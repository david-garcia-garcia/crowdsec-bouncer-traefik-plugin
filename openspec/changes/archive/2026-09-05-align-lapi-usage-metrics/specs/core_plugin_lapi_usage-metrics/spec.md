## Purpose

CrowdsecConnection reports remediation-component usage metrics to CrowdSec LAPI `POST /v1/usage-metrics` so `cscli metrics show bouncers` can slice this plugin like official bouncers.

## Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from `pkg/ip.GetRemoteIP` (MUST NOT parse `RemoteAddr` again). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Failure-action, stream-unhealthy, and technical drops with no decision SHALL omit `origin`. The plugin MUST NOT send a `scenario` item label. The plugin MUST NOT send `labels.type=traefik_plugin`.

#### Scenario: List decision drop
- **WHEN** a request is banned by a decision whose origin is `lists` and scenario is `firehol_level1`
- **THEN** the next usage-metrics POST includes a `dropped` item with `origin=lists:firehol_level1`, `ip_type` of the client, and `remediation=ban`

#### Scenario: AppSec drop
- **WHEN** AppSec remediates the request
- **THEN** the `dropped` item has `origin=appsec`

#### Scenario: Technical ban has no origin
- **WHEN** the bouncer bans because GetRemoteIP or the trusted-IP checker failed
- **THEN** the `dropped` item has `ip_type` when the address is known and omits `origin`

### Requirement: Processed counts every handled request
Each request the bouncer handles (trusted-IP bypass, pass, and drop) SHALL increment `processed` with unit `request` and label `ip_type` only. Disabled middleware MUST NOT increment. `processed` MUST NOT send `origin`.

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
