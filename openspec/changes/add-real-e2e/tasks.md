## 1. Checkout path for Yaegi on this fork

- [x] 1.1 In `.github/workflows/main.yml`, set the checkout `path` to `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` (the `go.mod` module path), not `github.com/${{ github.repository }}`. Set `defaults.run.working-directory` to the same path.

## 2. Pester real-stack suite from PR 273

- [x] 2.1 Add `Test-Integration.ps1`, `docker-compose.test.yml`, `tests/TestUtils.ps1`, and `tests/*.Tests.ps1` from branch `272`
- [x] 2.2 Pin Traefik to `traefik:v3.7.11` and Crowdsec to `crowdsecurity/crowdsec:v1.7.8`; replace `crowdseclapiurl` with `crowdseclapishost`; drop Traefik wget healthcheck
- [x] 2.3 Default Pester `TestPath` to `./tests/*.Tests.ps1` so mock e2e under `tests/e2e/` is not picked up
- [x] 2.4 Add `make e2e_pester` that runs `pwsh -File ./Test-Integration.ps1`

## 3. CI and docs

- [x] 3.1 Add a GitHub Actions job that runs `./Test-Integration.ps1`; keep the mock `make e2e_mock` job
- [x] 3.2 Add a README testing note for `./Test-Integration.ps1` without copying 273’s unrelated README churn
- [x] 3.3 Run existing local tests (`go test`); set `localTests` from the result
