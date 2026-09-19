## 1. LAPI version reporting

- [x] 1.1 Add a pkg/lapi httptest that constructs a Client with plugin version `v9.9.9-test`, POSTs usage-metrics, and asserts `remediation_components[0].version` is `v9.9.9-test`
- [x] 1.2 In that same fixture, assert the request `User-Agent` is `Crowdsec-Bouncer-Traefik-Plugin/v9.9.9-test`

## 2. AppSec User-Agent

- [x] 2.1 Add a pkg/appsec Query httptest that sets `pluginVersion` to `v9.9.9-test` on the Client and asserts outbound `User-Agent` is `Crowdsec-Bouncer-Traefik-Plugin/v9.9.9-test`

## 3. version.go wiring

- [x] 3.1 Add a root-package test that `New` against a mock LAPI sends `User-Agent` `Crowdsec-Bouncer-Traefik-Plugin/` plus the unexported `pluginVersion` from `version.go` (do not hardcode a release number)

## 4. Verify

- [x] 4.1 Run the new tests and the existing pkg/lapi and pkg/appsec tests
