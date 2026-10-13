# Requirement
IssueKey: 2026-09-18-fork-plugin-module-path

## Problem
This fork still identifies as `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` to Go, Yaegi, Traefik, and CI. Traefik cannot load this tree beside the upstream catalog plugin. Operators who keep maxlerebourg loaded cannot migrate to this fork as a second plugin.

## Current (code)
- `go.mod` module line is `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` (`go.mod`).
- Module-root and `pkg/` imports use that path (`plugin.go`, `pkg/bouncer/bouncer.go`, `pkg/lapi/client.go`, `pkg/appsec/client.go`, and the rest of the in-tree Go sources).
- `.traefik.yml` `import` is the old path; `displayName` is `Crowdsec Bouncer Traefik Plugin` (same family as upstream).
- Main CI checks out and runs under `go/src/github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin` (`.github/workflows/main.yml`). `e2e.yml` / `release-*.yml` do not hardcode that GOPATH. `Makefile` `yaegi_test` is `yaegi test -v .` (cwd only).
- Root `docker-compose.yml`, `examples/*/docker-compose.yml`, `examples/kubernetes/traefik/values.yml`, `examples/binary-vm/files/traefik/traefik.yml`, `tests/e2e/real/docker-compose.test.yml`, and `tests/e2e/mock/lib/{traefik.yml,common.sh}` still use the old `modulename` and/or `plugins-local/src/<old module>`.
- Those in-tree compose files register alias `bouncer` (`experimental.plugins.bouncer` / `localplugins.bouncer`) and dynamic `plugin.bouncer`. `examples/geoenrich-decisions/docker-compose.yml` already uses a second alias `geoblock` for `github.com/david-garcia-garcia/traefik-geoblock`.
- Live specs that SHALL the old import: `openspec/specs/build_ci_github_module-path/spec.md`, `openspec/specs/build_ci_github_race-detector/spec.md`, `openspec/specs/core_plugin_middleware_bouncer/spec.md`. `knowledge/devdocs/` has no old-import SHALL.
- Split already started: `README.md` static example and `docker-compose.local.yml` already use `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. README still documents alias `bouncer` / `plugin.bouncer`.
- `require github.com/david-garcia-garcia/traefik-middleware-utilities` is already this org (`go.mod`).

## Desired
Retarget this tree's Traefik/Yaegi module identity to `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` so it can load beside the upstream catalog plugin. Change `go.mod` `module`, every Go import of that module, `.traefik.yml` `import`, CI GOPATH checkout/working-directory, examples/docker-compose/e2e `modulename` and `plugins-local/src/<module>`, live OpenSpec/usage docs that SHALL the old import, and any yaegi_test/local-plugin path that hardcodes the old GOPATH.

`.traefik.yml` `displayName` SHOULD distinguish from upstream.

In-tree examples/e2e that only load this tree: change `modulename`; keep alias `bouncer` unless explore finds a compose collision. Document in README/usage that operators who keep upstream `plugins.bouncer` must register this fork under a different key (e.g. `experimental.plugins.crowdsec` + `plugin.crowdsec`).

## Affected
- Identity: `go.mod`, `plugin.go`, `pkg/**/*.go` imports, `.traefik.yml`
- CI: `.github/workflows/main.yml` (and any other workflow that later hardcodes the old GOPATH)
- Load paths: `docker-compose.yml`, `examples/**`, `tests/e2e/**`
- Live specs: `openspec/specs/build_ci_github_module-path`, `openspec/specs/build_ci_github_race-detector`, `openspec/specs/core_plugin_middleware_bouncer`
- Docs: `README.md` (collision note; moduleName already new)

## Out of scope
- Ban / captcha / LAPI behavior
- Catalog listing / publish to plugins.traefik.io
- Git remotes or GitHub repo name
- Historical `openspec/changes/archive/**` except live specs that still SHALL the old import
- Rename `pkg/` directories
- Retarget `github.com/david-garcia-garcia/traefik-middleware-utilities` or `traefik-geoblock`
- Invent a second in-tree middleware family unless explore finds a compose collision
- `renovate.json` `depNameTemplate` still `maxlerebourg/crowdsec-bouncer-traefik-plugin` (not listed on the ticket)

## Unknowns
- Catalog-form examples (`experimental.plugins.bouncer` + `version=v1.7.1`) will not download this unpublished fork after `modulename` changes. Explore must decide local bind-mount vs leave catalog pins vs accept broken catalog examples until an out-of-tree listing exists.
- Whether `displayName` text is specified beyond "distinguish from upstream".

## Tensions
- Ticket: change example `modulename`. Code: most examples load the *catalog* plugin at `v1.7.1`, not this tree. Ticket also: do not publish to plugins.traefik.io.
- Ticket: document a different operator key when keeping upstream `plugins.bouncer`. DestBranch README already uses the new moduleName *under* key `bouncer`.
- Ticket: live OpenSpec that SHALL the old import. Archive folders also contain the old path; ticket forbids rewriting those.
- DestBranch is already split: `docker-compose.local.yml` + README moduleName are new; `go.mod` / CI / examples / e2e / `.traefik.yml` are old.
