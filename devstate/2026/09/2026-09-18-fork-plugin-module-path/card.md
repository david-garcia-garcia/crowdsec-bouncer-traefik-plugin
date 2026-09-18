Developer review: ready for review — 2026-09-18T18:04:56Z

## What this changes
**Operators.** In-tree compose, e2e, Kubernetes values, and binary-vm now load this tree as `localPlugins.bouncer` at `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin` (bind-mount or a documented copy to `plugins-local/src/<module>`). Catalog `version=` pins of this module are gone. Hosts that already load upstream `experimental.plugins.bouncer` must register this fork under a different alias (`localPlugins.crowdsec` + `plugin.crowdsec`). `.traefik.yml` `displayName` is `CrowdSec Bouncer Traefik Plugin (david-garcia-garcia)`.

**Admin users.** None.

**Developers.** `go.mod` `module`, every in-tree import of this module, `.traefik.yml` `import`, and Main/race GOPATH checkout are `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`. Live specs name that path. Usage `core_plugin_middleware.md` now says keep `import` matching `go.mod`.

**End users.** None.

## Motivation
This ticket’s job is to give this tree its own Traefik/Yaegi module path so it can load beside the upstream catalog plugin. On DestBranch, `go.mod`, `.traefik.yml` `import`, Main CI GOPATH, and most compose/e2e load paths still say `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`. Traefik therefore treats this tree as the same plugin as upstream.

The DestBranch failure is a split identity: README and `docker-compose.local.yml` already name `github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin`, while the module, manifest, CI checkout, and catalog-form examples do not. Catalog examples pin `experimental.plugins.bouncer.version=v1.7.1`. A GET of this fork’s module at that catalog URL returns 404; the catalog will not list a fork. Changing only `modulename` on those catalog pins would make Traefik fail the download at startup.

Cost of not merging: this repo cannot be a second plugin. Operators stay on one identity (upstream catalog or a colliding GOPATH). CI/Yaegi keep resolving the old import.

```mermaid
flowchart TD
  Up["Upstream catalog plugin"] --> KeyB["experimental.plugins.bouncer"]
  Fork["This tree on DestBranch"] --> OldMod["moduleName maxlerebourg/..."]
  OldMod --> KeyB
  KeyB --> Collide["Same Traefik plugin key"]
  CatalogPin["Catalog pin with this fork moduleName"] --> DL["GET plugins.traefik.io public download"]
  DL --> Miss["404 — Traefik install fails"]
```

## Merge readiness
Apply landed on `b412e52`; Main, race, and both e2e jobs succeeded. 0 items remain.

Priority: P2 — operators cannot load this fork beside upstream without replacing it
Reviewed head: b412e52
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open reviewer comments |
| CI proof | 6/6 | Main, Race, and both e2e jobs succeeded |
| Local tests proof | N/A | `prHost` remote; CI proof covers remote |
| Review resolution | 6/6 | OPEN PR, no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-fork-plugin-module-path pushed | `git` `b412e52` on `origin` |
| OpenSpec | retarget-plugin-module-path | `openspec/changes/retarget-plugin-module-path/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/101 | pr-host List |
| CI | build 35377386877 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35377386877 ; e2e 35377387005 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35377387005 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no comments.md |

## Specs
- [core_plugin_middleware_local-plugin](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-fork-plugin-module-path/openspec/changes/retarget-plugin-module-path/proposal.md) — added
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-fork-plugin-module-path/openspec/changes/retarget-plugin-module-path/proposal.md) — modified
- [build_ci_github_module-path](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-fork-plugin-module-path/openspec/changes/retarget-plugin-module-path/proposal.md) — modified
- [build_ci_github_race-detector](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-fork-plugin-module-path/openspec/changes/retarget-plugin-module-path/proposal.md) — modified

## Follow-up issues
- [ ] [Retarget renovate depNameTemplate off maxlerebourg](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-fork-plugin-module-path/knowledge/debt/2026-09-18-renovate-depname-maxlerebourg.md) — renovate.json still templates maxlerebourg/crowdsec-bouncer-traefik-plugin; ticket left it out of scope.

## How this fits together
Local spec → branch `2026-09-18-fork-plugin-module-path` → stub PR 101 → apply `retarget-plugin-module-path` → CI on `b412e52` succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Catalog-form examples after modulename changes — local bind-mount, leave catalog pins, or accept broken catalog examples? | assumed — convert in-repo runnable compose to localPlugins + bind-mount at the new module path; keep alias bouncer; do not ship a catalog download of this fork | explore |
| What exact displayName text distinguishes from upstream? | assumed — CrowdSec Bouncer Traefik Plugin (david-garcia-garcia) | explore |
| Should README keep a catalog experimental.plugins snippet with version vX.Y.Z for this fork? | assumed — no as the working example; show localPlugins; mention 404 / fork-ban | explore |
| Should renovate.json depNameTemplate move in this change? | assumed — no. Ticket left it out of scope | explore |
| Should core_plugin_middleware_bouncer be renamed because “bouncer” is also the Traefik alias? | assumed — no. Update the import WHEN only | explore |

## Before merge
- [x] Apply `retarget-plugin-module-path` (module / manifest / CI GOPATH / localPlugins examples)
- [x] [P2] Document a different operator key when upstream `plugins.bouncer` is kept

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 3 modified | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b412e525eeed317cbf6f1e98fdc276b46c439941 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: `go.mod` is the identity owner; in-tree loads use localPlugins at that path because catalog GET of this module 404s and forks are not listed; alias `bouncer` stays in-tree.

Do we have a high-confidence way to reproduce? Yes — `origin/master` still has the old `go.mod` module and `.traefik.yml` `import`; this branch retargets both.

Is this the best way to solve the issue? Yes versus DestBranch — retarget plus localPlugins, not a catalog pin of this unpublished module.

### Evidence
What I checked:
- Dest HEAD `46a81d0` (`origin/master`)
- Reviewed HEAD `b412e525eeed317cbf6f1e98fdc276b46c439941`
- Local `go build ./...`, `go vet ./...`, `go test ./pkg/...`, `go test .` passed
- CI Main/Race 35377386877 success; e2e 35377387005 success
- First Main on `5629849` failed gofmt on `pkg/cache/zzz_cache_test.go`; fixed on `b412e52`
- PR 101; comment inventory empty
- qualify `qualified-with-gaps`

### Rank-up moves
None.
