## ADDED Requirements

### Requirement: GitHub Actions runs the Go race detector on pkg
The Main workflow SHALL include a job other than `main` that sets `CGO_ENABLED` to 1 and runs `go test -race -count=1 ./pkg/...`. That job SHALL use Go 1.22 and SHALL check out the repository under `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`. It MUST NOT set `CGO_ENABLED` to 0. It MUST NOT run `go test -race` on the module-root package.

#### Scenario: Pull request runs a race job
- **WHEN** a pull request triggers the Main workflow
- **THEN** a job other than Main Process runs `go test -race -count=1 ./pkg/...` with cgo enabled
- **AND** that job does not run the module-root suite under `-race`
