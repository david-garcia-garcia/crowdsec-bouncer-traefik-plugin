Developer review: needs changes — 2026-09-05T05:56:21.3177264Z

IssueKey: 2026-09-05-add-real-e2e
JobName: 2026-09-05-add-real-e2e

## What this changes
**Operators.** None yet (Docker e2e not landed). After implement: run `make e2e` for real Traefik + Crowdsec scenarios.

**Admin users.** None.

**Developers.** OpenSpec change `add-real-e2e` with specs `build_e2e_docker_crowdsec-stack` and `build_ci_github_module-path`. Product suite not applied yet.

**End users.** None.

## Motivation
`master` has no real-stack (Docker Traefik + Crowdsec) e2e. The closed upstream PR 273 never landed. Without this PR, this fork still cannot review or run that coverage against current `master`.

## Merge readiness
Propose artifacts are valid. Product apply and Yaegi checkout fix are not on HEAD yet. Main CI is still red. 4 items remain.

Priority: P3 — spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: e3700e1
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | Main CI failed; Docker suite not applied |
| CI proof | 2/6 | last measured Main failure; new HEAD not measured yet |
| Local tests proof | N/A | before implement (`localTests: none`) |
| Review resolution | 6/6 | no PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-real-e2e pushed | pending this propose push |
| OpenSpec | add-real-e2e | `openspec/changes/add-real-e2e/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/4 | pr-host |
| CI | build 33948208864 failure https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33948208864 ; build 33948208867 success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33948208867 | last measured |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | destate/comments.md absent |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
- [build_e2e_docker_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-real-e2e/openspec/changes/add-real-e2e/proposal.md) — added
- [build_ci_github_module-path](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-real-e2e/openspec/changes/add-real-e2e/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Ticket `2026-09-05-add-real-e2e` / PR #4. Propose is apply-ready. Next is copy PR 333’s Docker suite, pin images, run `make e2e` in CI, and fix Yaegi checkout path.

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
- [ ] Apply Docker e2e and Yaegi checkout tasks [P3]
- [ ] Wait for CI on PR #4 to succeed [P3]
- [ ] Drop the 🚧 WIP title when ready for review [P3]

## Findings
- [P3] Main Process failed on Yaegi because checkout uses `github.repository`. Path: `.github/workflows/main.yml:43`.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e3700e15222cea7f98099b70377fea8f12be99ca | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: port 333’s bash Docker suite onto current `master` and run it in this fork’s CI, instead of reviving stale Pester 273.

Do we have a high-confidence way to reproduce? Yes, `tests/e2e/scenarios/` is absent on `origin/master`; Main Yaegi fails on this fork.

Is this the best way to solve the issue? Yes versus `master` — the Makefile and mock README already describe the 333 layout.

### Evidence
What I checked:
- `openspec validate add-real-e2e --type change --strict` passed
- Specs `build_e2e_docker_crowdsec-stack` and `build_ci_github_module-path` (`openspec/changes/add-real-e2e/specs/`)

### Rank-up moves
None.
