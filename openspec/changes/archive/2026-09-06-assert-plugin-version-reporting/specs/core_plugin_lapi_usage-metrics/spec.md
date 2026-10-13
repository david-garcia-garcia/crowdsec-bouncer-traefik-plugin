## MODIFIED Requirements

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
