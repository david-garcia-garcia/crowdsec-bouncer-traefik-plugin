## MODIFIED Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from `pkg/ip.GetRemoteIP` (MUST NOT parse `RemoteAddr` again). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Drops with no CrowdSec decision SHALL send a plugin origin so they appear as `cscli metrics show bouncers` origin rows: `plugin:tech_getremotefail` when GetRemoteIP fails; `plugin:tech_trustipfail` when the trusted-IP checker fails; `plugin:tech_cachefail` when a cache error is fail-closed; `plugin:tech_streamfail` when stream is unhealthy; `plugin:lapi_failure` for live LAPI errors; `plugin:appsec_failure` for AppSec failure-action. Those paths MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, or `lists:`. Range-only cache hits SHALL send `origin` from the winning Range CIDR’s stored suffix when that suffix is present. A letter-only `range-index` line MAY omit `origin`. The plugin MUST NOT send a `scenario` item label. The plugin MUST NOT send `labels.type=traefik_plugin`.

#### Scenario: List decision drop
- **WHEN** a request is banned by a decision whose origin is `lists` and scenario is `firehol_level1`
- **THEN** the next usage-metrics POST includes a `dropped` item with `origin=lists:firehol_level1`, `ip_type` of the client, and `remediation=ban`

#### Scenario: Range-only stream drop uses stored origin
- **WHEN** stream has a Range ban whose origin is `crowdsec` and the client IP is inside that CIDR with no Ip or header hit
- **THEN** the `dropped` item has `origin=crowdsec` and `remediation=ban`

#### Scenario: Letter-only Range line omits origin
- **WHEN** `range-index` holds only `cidr=t` for a containing ban and the client IP has no Ip or header hit
- **THEN** the request is still banned and the `dropped` item MAY omit `origin`
