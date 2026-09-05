## Context

See `proposal.md` Why. `origin/master` already has `tests/e2e/mock/` and `make e2e_mock` in `.github/workflows/e2e.yml`. Makefile comments and the mock README describe a Docker suite under `tests/e2e/scenarios/` that is not on this branch. Upstream `feat/e2e-docker` (PR 333) has that suite. Closed PR 273 is a stale Pester stack. Main CI on this fork fails `yaegi_test` because checkout uses `github.repository`.

Client IP owner: Traefik `forwardedHeaders` plus plugin `forwardedHeadersTrustedIPs`. Tests send `X-Forwarded-For` only.

## Goals / Non-Goals

**Goals:**
- Land 333’s bash Docker scenarios on this `master`, with image tags from this tree’s examples.
- Run them in GitHub Actions on this fork.
- Fix Main checkout path so Yaegi works on this fork.

**Non-Goals:**
- Porting Pester 273.
- Changing bouncer runtime Go.
- Replacing mock e2e.
- Adding redis / tls-system-ca / scope-headers Docker scenarios (mock already covers those).
- Changing push-branch filters from `main` to `master`.

## Decisions

1. **Port 333, not 273.** Alternative: revive Pester. Rejected: current e2e is bash; 273 is Traefik v3.0.0 and old actions.
2. **Copy scenario layout from `upstream/feat/e2e-docker`**, then pin `traefik:v3.7.11` (333 used v3.7.1). Crowdsec stays `v1.7.8`.
3. **CI runs `make e2e`.** Alternative: local-only like 333. Rejected for this fork: the ticket’s done-when is a PR that passes CI with the real tests present. AppSec may pull collections; keep the scenario and accept longer CI.
4. **Keep 333’s test LAPI key** `40796d93c2958f9e58345514e67740e5` with `BOUNCER_KEY_TRAEFIK`.
5. **Checkout path** `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` in `.github/workflows/main.yml`. Alternative: rewrite the Go module path. Rejected: the plugin module name is the upstream import Traefik Yaegi uses.
6. **Sequential scenarios** with per-scenario Compose project names (`e2e-<name>`), shared `crowdsec` container name for `cscli`, host port `8000`. Same as 333.

## Risks / Trade-offs

- [Docker e2e slower / less deterministic than mock] → Keep mock as the fast job; Docker job is additional. Upload compose logs on failure (`/tmp/e2e-*.log` as 333 does).
- [AppSec collection download on first CI run] → Same as examples; healthcheck + `docker compose up --wait`. If it flakes, isolate AppSec in a follow-up — do not drop it from the first land.
- [Windows local] → Suite is bash + Docker. CI is ubuntu-latest. Local proof on Windows is WSL/bash if Docker engine is up; CI is the gate.
- [Hardcoded test bouncer key in compose] → Test-only fixture, same as 333/273. Not a production secret.

## Migration Plan

No runtime deploy. Merge adds test files and workflow jobs. Rollback is revert the PR. Mock e2e stays if Docker job is later disabled.
