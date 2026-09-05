## Why

This fork’s `master` CI only runs Traefik-binary + mock LAPI. That mock suite is not a substitute for real Traefik + Crowdsec. The author’s closed PR 273 added a **separate** Pester + Docker Compose stack; it never merged. Reviewers still cannot run real-stack coverage against current `master`.

## What Changes

- Add the Pester real-stack suite from PR 273 under `tests/e2e/real/` (sibling of `tests/e2e/mock/`).
- Keep `tests/e2e/mock/` and `make e2e_mock` unchanged as the mock suite.
- Run Pester in GitHub Actions on this fork (in addition to mock).
- Pin Traefik to `v3.7.11` and Crowdsec to `v1.7.8`. Map LAPI host with `crowdseclapishost` (273’s `crowdseclapiurl` is not a field on this tree).
- Pin Main workflow checkout path to the Go module path so `yaegi_test` works on this fork.
- Do not land bash `tests/e2e/scenarios/` from upstream PR 333. Do not change bouncer runtime Go.

## Capabilities

### New Capabilities

- `build_e2e_pester_crowdsec-stack`: Pester + Docker Traefik + Crowdsec integration suite and the CI job that runs it.
- `build_ci_github_module-path`: GitHub Actions Main job checks out the plugin at the Go module path so Yaegi can load it on forks.

### Modified Capabilities

None. `openspec/specs/` is empty on `origin/master`.

## Impact

- New `tests/e2e/real/` (`Test-Integration.ps1`, `docker-compose.test.yml`, `*.Tests.ps1`, `TestUtils.ps1`).
- `.github/workflows/e2e.yml` (new Pester job) and `.github/workflows/main.yml` (checkout path).
- Optional `make e2e_pester`. Mock Makefile targets stay.
- README testing note for `tests/e2e/real/Test-Integration.ps1`.
- Bootstrap `openspec/specs/domains.md` for `build` / `e2e` and `build` / `ci`.
- No bouncer API or ServeHTTP change. No bash 333 scenarios.
