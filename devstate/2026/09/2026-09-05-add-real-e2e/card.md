Developer review: needs changes — 2026-09-05T05:53:08.4626156Z

IssueKey: 2026-09-05-add-real-e2e
JobName: 2026-09-05-add-real-e2e

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore decided to port the bash Docker e2e suite (`tests/e2e/scenarios/`) from upstream PR 333 onto this fork’s `master`, run it in GitHub Actions, and pin Traefik checkout for Yaegi on the fork. Product files not landed yet.

**End users.** None.

## Motivation
`master` has no real-stack (Docker Traefik + Crowdsec) e2e. The closed upstream PR 273 never landed. Without this PR, this fork still cannot review or run that coverage against current `master`.

## Merge readiness
Explore wrote proceed policies. Main CI on this fork is red (Yaegi module path). Product e2e is not on the branch yet. 5 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: ed4cb9b
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | Main CI failed; Docker suite not landed |
| CI proof | 2/6 | Main Process failed; e2e mock succeeded |
| Local tests proof | N/A | before implement (`localTests: none`) |
| Review resolution | 6/6 | no PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-real-e2e pushed | `git` origin/2026-09-05-add-real-e2e |
| OpenSpec | none | `openspec/` absent on `origin/master` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/4 | pr-host |
| CI | build 33948208864 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33948208864 ; build 33948208867 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33948208867 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | destate/comments.md absent |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-05-add-real-e2e` is a new branch from `origin/master` with stub PR #4. Explore chose bash Docker e2e from upstream #333, CI `make e2e` on this fork, and a Yaegi checkout-path fix so Main can go green.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Which implementation to land — Pester 273, bash 333, or a hybrid? | assumed — port bash Docker suite from `upstream/feat/e2e-docker` (PR 333); do not port Pester 273 | explore |
| Should GitHub Actions in this repo run the Docker suite, or keep it local-only like 333? | assumed — run `make e2e` in CI on this fork; keep `make e2e_mock` | explore |
| Which Traefik / Crowdsec image tags? | assumed — `traefik:v3.7.11` and `crowdsecurity/crowdsec:v1.7.8` | explore |
| Who already owns the client address the bouncer remediates in these tests? | assumed — Traefik `forwardedHeaders` plus plugin `forwardedHeadersTrustedIPs`; tests send `X-Forwarded-For` only | explore |
| Should push workflows also list `master`? | assumed — do not change push branch filters; PR into `master` already runs jobs | explore |
| Keep 333’s well-known test LAPI key? | assumed — yes; test fixture with `BOUNCER_KEY_TRAEFIK` | explore |
| Main CI Yaegi path vs fork `github.repository`? | assumed — pin checkout path to the Go module path so Yaegi finds the plugin | explore |

## Before merge
- [ ] Land Docker e2e under `tests/e2e/scenarios/` and `make e2e` [P3]
- [ ] Run Docker e2e in GitHub Actions on this fork [P3]
- [ ] Fix Main Yaegi checkout path so CI can succeed on this fork [P3]
- [ ] Wait for CI on PR #4 to succeed [P3]
- [ ] Drop the 🚧 WIP title when ready for review [P3]

## Findings
- [P3] Main Process failed on Yaegi: import path `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pkg/cache` not found because checkout uses `github.repository` (`david-garcia-garcia/...`). Path: `.github/workflows/main.yml:43`.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ed4cb9beea83c2003d44ddb8fb9d1ac3d149ae87 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: port 333’s bash Docker suite onto current `master` and run it in this fork’s CI, instead of reviving stale Pester 273.

Do we have a high-confidence way to reproduce? Yes, `tests/e2e/scenarios/` is absent on `origin/master`; Main Yaegi fails on this fork’s checkout path.

Is this the best way to solve the issue? Yes versus `master` — the Makefile and mock README already describe the 333 layout.

### Evidence
What I checked:
- `upstream/feat/e2e-docker` seven scenarios + `make e2e` (`git show`)
- Examples pin `traefik:v3.7.11` and `crowdsecurity/crowdsec:v1.7.8` (`docker-compose.yml`)
- Mock Traefik pin `v3.7.11` (`tests/e2e/mock/lib/common.sh`)
- `openspec/` not on `origin/master` (`git ls-files`)
- Main failed 33948208864; e2e mock succeeded 33948208867 (`get_check_runs`)

### Rank-up moves
None.
