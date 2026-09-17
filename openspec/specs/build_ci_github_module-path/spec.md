## Purpose

Makes GitHub Actions Main check out this plugin at its Go module path so Yaegi tests resolve the same import path on forks as on the upstream repository.

## Requirements

### Requirement: Checkout path matches the Go module path
The Main GitHub Actions workflow SHALL check out the repository under `go/src/` at the path equal to the module path in `go.mod` (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`), not `github.com/${{ github.repository }}`.

#### Scenario: Yaegi finds pkg/cache on this fork
- **WHEN** Main runs `make yaegi_test` on a pull request in `david-garcia-garcia/crowdsec-bouncer-traefik-plugin`
- **THEN** Yaegi loads `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache` from the checkout and the job does not fail with “unable to find source related to” that import
