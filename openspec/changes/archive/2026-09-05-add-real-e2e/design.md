## Context

See `proposal.md` Why. `origin/master` already has `tests/e2e/mock/` (bash, mock LAPI). Closed PR 273 has Pester + `docker-compose.test.yml`. Upstream PR 333 has a third bash Docker layout; the human rejected substituting it for 273.

Client IP owner: Traefik `forwardedHeaders` plus plugin `forwardedHeadersTrustedIPs`. Tests send `X-Forwarded-For` only.

273 used `crowdseclapiurl`; this tree uses `crowdseclapishost` (default `crowdsec:8080`).

## Goals / Non-Goals

**Goals:**
- Land 273’s Pester suite on this `master`, with current image tags and current LAPI host labels.
- Run it in GitHub Actions next to mock e2e.
- Fix Main checkout path so Yaegi works on this fork.

**Non-Goals:**
- Landing bash `tests/e2e/scenarios/` from PR 333.
- Replacing or deleting mock e2e.
- Changing bouncer runtime Go.
- Copying 273’s unrelated README mermaid / config-table churn.

## Decisions

1. **Pester 273, not bash 333.** Human: mock and real are different suites; keep them separate; use PowerShell like the original proposal.
2. **Pin `traefik:v3.7.11` and `crowdsecurity/crowdsec:v1.7.8`.** 273 had Traefik v3.0.0 and Crowdsec v1.6.8.
3. **Replace `crowdseclapiurl` with `crowdseclapishost=crowdsec:8080`.** Unknown Traefik labels are ignored; the Go field is host/scheme/path.
4. **Real suite lives in `tests/e2e/real/`.** Sibling of `tests/e2e/mock/`. Default Pester path is that folder’s `*.Tests.ps1`. Compose bind-mounts the repository root for the local plugin.
5. **CI job uses runner `pwsh`** (ubuntu-latest includes PowerShell) and `Install-Module Pester`. Do not apt-install Microsoft packages unless `pwsh` is missing.
6. **Remove Traefik wget healthcheck.** Traefik v3.7 images do not ship wget; `Test-Integration.ps1` already polls the API.
7. **Checkout path** `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` in Main.

## Risks / Trade-offs

- [Pester on Ubuntu needs the module] → Install-Module in the job and in `Test-Integration.ps1`.
- [Real Crowdsec slower than mock] → Separate CI job so mock still finishes fast; upload `test-results.xml` and container logs on failure.
- [273 trusted CIDR / test IPs] → Keep 273’s `X-Forwarded-For` + `forwardedHeadersTrustedIPs` unless CI proves they no longer match Docker’s gateway.

## Migration Plan

No runtime deploy. Merge adds test files and a CI job. Rollback is revert. Mock e2e stays if the Pester job is later disabled.
