## Purpose

CrowdsecConnection reports remediation-component usage metrics to CrowdSec LAPI `POST /v1/usage-metrics` so `cscli metrics show bouncers` can slice this plugin like official bouncers.

## Requirements

### Requirement: Dropped items use official labels
Each dropped request SHALL increment a `dropped` item with unit `request`. Labels SHALL include `ip_type` (`ipv4` or `ipv6`) from the `net.IP` `pkg/ip.GetRemoteIP` already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). The request path MUST NOT parse `RemoteAddr` again and MUST NOT classify `ip_type` by parsing the client string (`ip.Family` on the string). When the drop applies a LAPI or AppSec remediation, labels SHALL include `remediation` (`ban` or `captcha`). `origin` SHALL be the decision origin, except CrowdSec `lists` origin SHALL be sent as `lists:` plus the decision scenario. AppSec remediations SHALL use `origin=appsec`. Drops with no CrowdSec decision SHALL send a plugin origin so they appear as `cscli metrics show bouncers` origin rows: `plugin:tech_getremotefail` when GetRemoteIP fails; `plugin:tech_trustipfail` when the trusted-IP checker fails; `plugin:tech_cachefail` when a cache error is fail-closed; `plugin:tech_streamfail` when stream is unhealthy; `plugin:lapi_failure` for live LAPI errors; `plugin:appsec_failure` for AppSec failure-action. Those paths MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, or `lists:`. Range-only cache hits SHALL send `origin` from the winning Range CIDR’s stored suffix when that suffix is present. A letter-only `range-index` line MAY omit `origin`. The plugin MUST NOT send a `scenario` item label. The plugin MUST NOT send `labels.type=traefik_plugin`.

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

### Requirement: Processed counts every handled request
Each request the bouncer handles (trusted-IP bypass, pass, and drop) SHALL increment `processed` with unit `request` and label `ip_type` only, classified from the `net.IP` GetRemoteIP already yielded (`To4()` non-nil is ipv4, otherwise ipv6; empty when that parse is missing). Disabled middleware MUST NOT increment. `processed` MUST NOT send `origin`. The request path MUST NOT classify `processed` `ip_type` by parsing the client string.

#### Scenario: Allowed request is processed
- **WHEN** a non-trusted client is allowed through
- **THEN** the next POST includes `processed` with that client's `ip_type`

### Requirement: Active decisions are a stream/alone gauge
In stream and alone modes, `active_decisions` SHALL be a gauge (unit `ip`) of Ip and header-scope decision records this connection currently applies, labeled `origin` (lists-rewritten) and `ip_type` of the decision value. Range CIDRs SHALL be omitted from this gauge until Range exact-CIDR forget lands. Live, none, and AppSec-only modes SHALL omit `active_decisions`. The gauge MUST NOT expand a CIDR into host addresses. Counts SHALL come from a DecisionStore snapshot at POST, not from a reporter-held per-slot map. Memory PublishTick expiry and Redis TTL without DeleteMany MUST NOT decrement the gauge.

#### Scenario: Stream IP ban is counted
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Range CIDR is omitted from the gauge
- **WHEN** stream applies one Range ban whose value is `10.0.0.0/8` and origin is `crowdsec`
- **THEN** the next `active_decisions` window does not include that CIDR

### Requirement: Envelope identity
The remediation-component object SHALL send `version` from the plugin version, `type` `bouncer`, `name` `traefik_plugin`, `feature_flags` as an empty JSON array, and `utc_startup_timestamp` from connection start (MUST NOT be `time.Now()` at each push). User-Agent SHALL remain `Crowdsec-Bouncer-Traefik-Plugin/<version>`. `metrics` SHALL be a JSON array of windows. The plugin version SHALL be the value `version.go` defines and the module-root constructor passes into the LAPI Client.

#### Scenario: Startup timestamp is stable
- **WHEN** two usage-metrics POSTs occur from the same connection
- **THEN** both send the same `utc_startup_timestamp`

#### Scenario: Usage-metrics version is the plugin version
- **WHEN** a LAPI Client constructed with plugin version `v9.9.9-test` POSTs usage-metrics
- **THEN** `remediation_components[0].version` is `v9.9.9-test`

#### Scenario: LAPI User-Agent includes the plugin version
- **WHEN** that Client sends a LAPI HTTP request (including usage-metrics)
- **THEN** the request `User-Agent` is `Crowdsec-Bouncer-Traefik-Plugin/v9.9.9-test`

#### Scenario: Constructor reports version.go
- **WHEN** the module-root constructor builds a LAPI-backed middleware
- **THEN** LAPI requests use `User-Agent` `Crowdsec-Bouncer-Traefik-Plugin/` plus the `pluginVersion` string in `version.go`
- **AND** that assertion MUST NOT hardcode a release number

### Requirement: MetricsReporter owns the usage-metrics window
The dropped window, processed atomics, last successful push time, and the POST/restore path SHALL live on a `MetricsReporter` that `Client` holds. `Client` MUST NOT keep those window fields on itself. The reporter MUST NOT keep `activeDecisionSlots` or `activeDecisionsByOriginIPType`. `IncProcessed`, `IncDropped`, `reportMetrics`, and `drainMetrics` SHALL remain `Client` methods that forward to that reporter. Envelope identity (`utc_startup_timestamp`, plugin version, mode) SHALL be snapshotted onto the reporter at construct and MUST NOT be `time.Now()` at each push. Stream/alone `reportMetrics` SHALL snapshot DecisionStore active counts and MUST NOT restore those counts on a failed POST (they are a gauge, not a window counter).

#### Scenario: Window survives transport replace
- **WHEN** a Client has unsent dropped or processed counts and a later bind replaces LAPI HTTP+auth
- **THEN** the next usage-metrics POST still includes those counts
- **AND** the POST uses the replaced transport

#### Scenario: Startup timestamp stays on the reporter
- **WHEN** two usage-metrics POSTs occur from the same Client
- **THEN** both send the same `utc_startup_timestamp`
- **AND** that value is the construct snapshot, not `time.Now()` at push

### Requirement: Usage-metrics POST uses the replaceable LAPI transport
The reporter SHALL POST `v1/usage-metrics` through the Client LAPI query that loads the current transport on every call. The reporter MUST NOT store `*http.Client`. New atomic fields MUST use `atomic.Value` with a Yaegi why-comment, not `atomic.Pointer[T]`. Write-once Client scalars, including `metricsInterval`, MUST NOT become mutable.

#### Scenario: POST after transport replace
- **WHEN** `AdoptTransport` stores a new transport and a usage-metrics POST runs
- **THEN** the request uses that transport’s HTTP client and auth header
- **AND** the reporter has no `*http.Client` field

### Requirement: Usage-metrics share the Client reclaim lifetime
`Client` SHALL hold one `MetricsReporter` on the same reclaim table entry as the stream cursor. `Sleep`, `Wake`, and `Close` SHALL start and stop the existing metrics ticker with the same `startTicker` helper. The plugin MUST NOT open a second reclaim entry or a second metrics ticker for usage-metrics. `metricsInterval` SHALL stay a write-once Client scalar. `drainMetrics` SHALL no-op when that interval is `<= 0`. Sleep SHALL POST remaining counters asynchronously. Close SHALL POST them synchronously before idle HTTP is closed. A failed POST SHALL restore the window for the next drain or ticker.

#### Scenario: Sleep drains on the same Client
- **WHEN** the last constructor context ends and reclaim Sleeps
- **THEN** the existing metrics ticker stops
- **AND** remaining window counters POST asynchronously
- **AND** no second reclaim key is created for metrics

#### Scenario: Wake resumes the same ticker
- **WHEN** Open during grace Wakes the same Client and `metricsInterval` is greater than 0
- **THEN** the same `startTicker` helper starts the metrics ticker
- **AND** the reporter field is the same instance

### Requirement: Active-decision slots store intern id and family
In stream and alone modes, DecisionStore SHALL keep compact origin-id × family counts. The reporter MUST NOT keep a per-slot forget map. `reportMetrics` SHALL snapshot store counts and send lists-rewritten origin names via `OriginName` at POST. When intern overflowed, that origin id is `0` and `OriginName` is empty (no leftover origin string). Live, none, and AppSec-only modes SHALL omit `active_decisions` items. The intern table owner is DecisionStore; the reporter MUST NOT own a second intern table. Stream apply MUST NOT remember or forget Ip, header, or Range keys on the reporter. PutMany and DeleteMany SHALL Peek then adjust those counts on the Store; engines MUST NOT increment or decrement.

#### Scenario: Stream IP ban still posts origin name
- **WHEN** stream applies one Ip ban whose value is `1.2.3.4` and origin is `crowdsec`
- **THEN** `active_decisions` includes 1 with `origin=crowdsec` and `ip_type=ipv4`

#### Scenario: Forget drops that slot
- **WHEN** stream later deletes that same Ip slot
- **THEN** the next `active_decisions` window omits that record

#### Scenario: Overflow posts empty origin name
- **WHEN** intern overflowed and stream applies an Ip ban
- **THEN** `active_decisions` origin for that slot is empty

### Requirement: Forced-decision drops use plugin origin
When the bouncer remediates because a configured `crowdsecDecisionHeader` forced `b` or `c`, the `dropped` item SHALL send `origin=plugin:forced_decision`. It MUST NOT reuse `crowdsec`, `cscli`, `CAPI`, `appsec`, `lists:`, or the tech/lapi/appsec failure origins. Ban and captcha remediations still send `remediation=ban` or `remediation=captcha`. A gated-OK captcha that reaches the next handler MUST NOT increment `dropped` for that force.

#### Scenario: Forced ban drop uses plugin origin
- **WHEN** a non-trusted client is banned because `crowdsecDecisionHeader` forced `b`
- **THEN** the `dropped` item has `origin=plugin:forced_decision` and `remediation=ban`

#### Scenario: Forced captcha drop uses plugin origin
- **WHEN** a non-trusted client is shown captcha because `crowdsecDecisionHeader` forced `c` and the gate cookie is not valid
- **THEN** the `dropped` item has `origin=plugin:forced_decision` and `remediation=captcha`
