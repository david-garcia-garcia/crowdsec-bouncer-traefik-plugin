## Why

This fork’s `master` has no real-stack end-to-end suite: CI only runs Traefik-binary + mock LAPI. Operators and reviewers cannot see the plugin load as a Traefik local plugin against a real Crowdsec LAPI. The author’s closed upstream PR 273 never merged; current `master` already documents a bash Docker layout (`tests/e2e/scenarios/`, `make e2e`) that is still absent.

## What Changes

- Add a Docker Compose e2e suite (real Traefik + real Crowdsec) under `tests/e2e/scenarios/`, ported from upstream PR 333 onto current `master`.
- Wire `make e2e` / `make e2e_<scenario>` next to existing `make e2e_mock`.
- Run `make e2e` in GitHub Actions on this fork (in addition to mock e2e).
- Pin Traefik to `v3.7.11` and Crowdsec to `v1.7.8` (this tree’s examples), not 333’s older Traefik tag.
- Pin Main workflow checkout path to the Go module path so `yaegi_test` works when `github.repository` is this fork.
- Keep the mock suite. Do not port Pester 273. Do not change bouncer runtime Go.

## Capabilities

### New Capabilities

- `build_e2e_docker_crowdsec-stack`: Docker Traefik + Crowdsec scenario suite, Makefile targets, and CI job that runs it.
- `build_ci_github_module-path`: GitHub Actions Main job checks out the plugin at the Go module path so Yaegi can load it on forks.

### Modified Capabilities

None. `openspec/specs/` is empty on `origin/master`.

## Impact

- New files under `tests/e2e/scenarios/` and `tests/e2e/lib/` (Docker suite, not mock).
- `Makefile` e2e targets.
- `.github/workflows/e2e.yml` (Docker job) and `.github/workflows/main.yml` (checkout path).
- Docs that currently say the Docker suite lives in a separate PR (`tests/e2e/mock/README.md`, Makefile comments).
- Bootstrap `openspec/specs/domains.md` for `build` / `e2e` and `build` / `ci`.
- No bouncer API, config, or ServeHTTP change. No Pester. No upstream PR.
