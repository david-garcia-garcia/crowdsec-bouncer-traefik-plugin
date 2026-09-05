# Requirement
IssueKey: 2026-09-05-add-real-e2e

## Problem

This fork has no real-stack end-to-end suite on `master`. CI already runs a
Traefik-binary + mock-LAPI suite. The author's closed upstream PR
[maxlerebourg/crowdsec-bouncer-traefik-plugin#273](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/273)
added Docker Traefik + real Crowdsec coverage (Pester) and was never merged.
The caller wants that work reviewed as a **new PR in this repo against
`master`**, not against upstream `main`. Done when that PR's CI succeeds and
the delivery card is published.

## Current (code)

- Mock e2e (Traefik binary + `mocklapi`, no Docker, no Crowdsec) lives at
  `tests/e2e/mock/` and is what CI runs: `.github/workflows/e2e.yml` (`make
  e2e_mock`). Documented in `tests/e2e/mock/README.md`.
- `Makefile` `e2e_mock` / `e2e_mock_%` targets exist. Comments say a local
  Docker suite (`make e2e`, `tests/e2e/scenarios`) lives in a separate PR.
  `tests/e2e/scenarios/` is **not found** on `origin/master` (`23ce76d`).
- Push triggers for Main and E2E workflows list `branches: [main]` only.
  `pull_request:` has no branch filter, so a PR into `master` still runs those
  jobs. `.github/workflows/main.yml`, `.github/workflows/e2e.yml`.
- Old PR 273 head `272` adds `Test-Integration.ps1`, `docker-compose.test.yml`,
  `tests/*.Tests.ps1`, a Main workflow `integration` job (PowerShell + Pester),
  and a README note. That tree is **not** on `master`. Compose uses
  `traefik:v3.0.0`, a hardcoded LAPI key `40796d93c2958f9e58345514e67740e5`,
  and Docker socket bind-mount for Traefik.
- Upstream PR 333 (`feat/e2e-docker`) is a bash + Compose real-stack suite
  (`tests/e2e/scenarios/`, `make e2e`). Open, mergeable_state dirty, **not** on
  this `master`. Current mock README points at that PR as local-only.

## Desired

- A new branch from current `origin/master` named `2026-09-05-add-real-e2e`.
- One OPEN PR in `david-garcia-garcia/crowdsec-bouncer-traefik-plugin` with
  base `master` (not `maxlerebourg` / upstream).
- Real-stack e2e (Traefik + real Crowdsec) implementation and tests present on
  that branch so they can be reviewed.
- CI on that PR succeeds; delivery card published on the PR summary.

## Affected

- New or restored e2e harness (path TBD in explore: Pester 273 vs bash 333 vs
  a port onto `tests/e2e/`).
- Possibly `.github/workflows/*` if real-stack tests must run in CI for this
  repo's PR to go green.
- `Makefile` e2e targets.
- Docs that currently say the Docker suite is absent / local-only
  (`tests/e2e/mock/README.md`, `Makefile` comments).

## Out of scope

- Reopening or updating upstream PR 273 or 333.
- Changing bouncer runtime behavior (273 stated tests-only).
- Replacing or deleting the mock CI suite unless a later phase proves it
  blocks landing real-stack coverage.
- Opening the PR against `maxlerebourg/crowdsec-bouncer-traefik-plugin`.

## Unknowns

- Which implementation to land: stale Pester 273, bash Docker 333, or a
  rebased hybrid on current Traefik / Crowdsec images.
- Whether GitHub Actions in **this** repo should run the Docker suite (273
  did; 333 and current mock README say local-only). Caller asked for a PR that
  **passes CI**; that can be true with mock-only CI if Docker stays local.
- Whether push workflows should also list `master` (PRs still run today).

## Tensions

- Master already has mock e2e in CI; 273 would add a second, heavier
  PowerShell integration job on Ubuntu.
- Current in-tree e2e is bash; 273 is Pester. 333 matches the bash layout the
  Makefile already describes.
- 273 is stale vs `master` (Traefik v3.0.0, Go 1.23 in that workflow copy,
  old action majors; this repo is Go 1.22 / Traefik binary v3.7.1 in the mock
  suite).
- 273 compose ships a hardcoded Crowdsec LAPI key in repo files.
