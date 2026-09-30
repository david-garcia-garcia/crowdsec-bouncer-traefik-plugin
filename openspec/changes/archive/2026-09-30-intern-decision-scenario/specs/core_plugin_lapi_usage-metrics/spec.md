## MODIFIED Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from the `net.IP` `pkg/ip.GetRemoteIP` already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). The request path MUST NOT parse `RemoteAddr` again and MUST NOT classify `ip_type` by parsing the client string (`ip.Family` on the string). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Drops with no CrowdSec decision SHALL send a plugin origin so they appear as `cscli metrics show bouncers` origin rows: `plugin:tech_getremotefail` when GetRemoteIP fails; `plugin:tech_trustipfail` when the trusted-IP checker fails; `plugin:tech_cachefail` when a cache error is fail-closed; `plugin:tech_streamfail` when stream is unhealthy; `plugin:lapi_failure` for live LAPI errors; `plugin:appsec_failure` for AppSec failure-action. Those paths MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, or `lists:`. Range-only cache hits SHALL send `origin` from the winning Range CIDR’s stored suffix when that suffix is present. A letter-only `range-index` line MAY omit `origin`. The plugin MUST NOT send a `scenario` item label, including when the DecisionStore has interned the raw LAPI scenario. The plugin MUST NOT send `labels.type=traefik_plugin`.

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

#### Scenario: Interned scenario is not a label
- **WHEN** stream has interned a raw LAPI scenario on an Ip ban and that ban drops a request
- **THEN** the `dropped` item has no `scenario` label
- **AND** `origin` is still the folded metrics origin

### Requirement: Active-decision slots store intern id and family
In stream and alone modes, DecisionStore SHALL keep compact origin-id × family counts. The reporter MUST NOT keep a per-slot forget map. `reportMetrics` SHALL snapshot store counts and send lists-rewritten origin names via `OriginName` at POST. When intern overflowed, that origin id is `0` and `OriginName` is empty (no leftover origin string). Live, none, and AppSec-only modes SHALL omit `active_decisions` items. DecisionStore SHALL own the origin intern table and the scenario intern table; the reporter MUST NOT own either intern table. Stream apply MUST NOT remember or forget Ip, header, or Range keys on the reporter. PutMany and DeleteMany SHALL Peek then adjust those counts on the Store; engines MUST NOT increment or decrement.

#### Scenario: Stream IP ban still posts origin name
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Forget drops that slot
- **WHEN** stream later deletes that same Ip slot
- **THEN** the next `active_decisions` window omits that record

#### Scenario: Overflow posts empty origin name
- **WHEN** intern overflowed and stream applies an Ip ban
- **THEN** `active_decisions` origin for that slot is empty
