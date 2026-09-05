Developer review: in progress — 2026-09-05T06:55:52.156Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore design for a thinned Yaegi root package, `pkg/crowdsecconnection`, and `pkg/bouncer`, plus Traefik constructor research under `knowledge/research/ext_traefik_plugins_yaegi-constructor/`. No plugin runtime vs `master`.

**End users.** None.

## Motivation
On `master`, Traefik still constructs one handler per router while stream ticker, cache, and LAPI health live as process globals mixed into `Bouncer`. Empty `TestNew` / stream tables cannot pin that lifetime. Without this split the first-wins connection stays implicit and untested.

## Merge readiness
Explore written; waiting on design agreement. Not ready for review. 2 items remain.

Priority: P3 — internal lifetime split and tests; no current operator or end-user harm
Reviewed head: 67a304a
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore assumed decisions still need a human; e2e CI in progress |
| CI proof | 3/6 | Main Process succeeded; both e2e jobs still running |
| Local tests proof | N/A | Before implement; remote PR |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `67a304af4adaa0cf48997d9d459876a9dbee7e54` |
| OpenSpec | none | `openspec/changes/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | build 33951126475 Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951126475/job/101265968144 ; build 33951126474 e2e (docker + pester) in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951126474/job/101265977902 ; build 33951126474 e2e (binary + mock LAPI) in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33951126474/job/101265977989 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | no codereview.md |
| Performance | None. | no codereview.md |

## Specs
None.

## Follow-up issues
- [ ] [take] [small] Empty `TestNew` / stream / query tables in `bouncer_test.go` — replace in this change.
- [ ] [note] [large] `pkg/cache` process-wide `ttl_map` — fine for one Connection; risk if connections are keyed later.
- [ ] [note] [large] `pkg/logger` never closes `OpenFile`; Windows logging tests fail TempDir cleanup.

## How this fits together
Worktree from `origin/master`. Stub PR #6 is the durable card. Explore proposed the split; this run stops here for agreement before propose.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go; do not change .traefik.yml import | explore |
| One CrowdsecConnection per process, or one per LAPI identity? | assumed — one per process, first New wins | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer; cache via Connection | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |
| How far does exquisite coverage go beyond compiled tests? | assumed — go test + fake LAPI owns lifetime; existing e2e stays Yaegi proof | explore |

## Before merge
- [ ] Agree the explore design (this stop) before propose
- [ ] Wait for e2e CI on PR #6 (still in progress)

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No spec.md vs master |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 67a304af4adaa0cf48997d9d459876a9dbee7e54 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Thin the Yaegi root package; give stream/cache/LAPI to a process `CrowdsecConnection`; keep per-router `Bouncer` as the request handler. Matches Traefik `New`-per-router and today’s first-wins globals without a catalog import change.

Do we have a high-confidence way to reproduce? Yes — `bouncer.go` globals and empty `TestNew` on `master`; Traefik middleware loader sourced in `ext_traefik_plugins_yaegi-constructor`.

Is this the best way to solve the issue? Yes vs `master`, if the assumed decisions stand: moving `New` into a subpackage would fight Yaegi lookup; keying connections would change operator-visible first-wins.

### Evidence
What I checked:
- Traefik Yaegi constructor (`knowledge/research/ext_traefik_plugins_yaegi-constructor/notes.md`, Traefik `middlewareyaegi.go` at faa1eb59)
- `bouncer.go` 47–73, 128–331, 336–414, 501–326
- `go test ./...` on this worktree: pkg tests ok; root FAIL Windows log-file TempDir cleanup only
- PR #6 checks: Main Process success, both e2e in_progress (GitHub `get_check_runs`)

### Rank-up moves
None.
