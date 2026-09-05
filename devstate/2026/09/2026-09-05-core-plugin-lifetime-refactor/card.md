Developer review: in progress — 2026-09-05T08:21:46.900Z

## What this changes
**Operators.** Two Crowdsec bouncer middlewares in one Traefik now keep isolated LAPI streams and caches. Same connection fields still share one backend; different LAPI/mode/redis/interval are two live backends. Watch debug lines `reclaim_put|bind|orphan|reclaim|dispose`.

**Admin users.** None.

**Developers.** Root `plugin.go` `New` reclaims `*crowdsecconnection.CrowdsecConnection` by connection-field hash (not middleware name) and returns `pkg/bouncer` ForRoute. Memory cache is per Client; Redis keys are prefixed with that identity. Mock e2e `dual-bouncer` covers two middlewares / two LAPIs.

**End users.** A client IP can be banned on one Crowdsec backend and allowed on another in the same Traefik process.

## Motivation
On `master`, stream ticker, decision cache, and LAPI health are process globals, so a second Crowdsec bouncer config in the same Traefik is first-wins. Operators cannot run two backends or compare configs side-by-side. Without this change that sharing stays the product.

## Merge readiness
Implement is on `a72cb8c` with green CI. Code review, usage docs, and archive still remain. 3 items remain.

Priority: P2 — operators cannot run two Crowdsec configs in one Traefik; workaround is a second Traefik
Reviewed head: a72cb8c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded on the implement head |
| CI proof | 6/6 | All three required checks succeeded on `a72cb8c` |
| Local tests proof | N/A | Remote PR; CI covers it |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `a72cb8c374fa227d27503352c19886bbe5888d91` |
| OpenSpec | crowdsec-connection-bouncer-split | `openspec/changes/crowdsec-connection-bouncer-split/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33954888144/job/101276285360 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33954888143/job/101276285745 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33954888143/job/101276285558 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests (`go test` except known Windows log TempDir) |
| PR comments | no comments | GitHub PR comments |
| Security | None. | no codereview.md yet |
| Performance | None. | no codereview.md yet |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added
- [build_e2e_mock_dual-bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/crowdsec-connection-bouncer-split/proposal.md) — added

## Follow-up issues
- [ ] [take] [small] Empty `TestNew` / stream / query tables — Implement: replaced in plugin_test.go (`f116ac8`).
- [ ] [take] [small] Isolated cache — Implement: per-Client map + Redis prefix (`f116ac8`).
- [ ] [take] [small] Mock e2e dual-bouncer — Implement: `tests/e2e/mock/scenarios/dual-bouncer/` (`f116ac8`).
- [ ] [note] [large] `pkg/logger` never closes `OpenFile`; Windows logging tests fail TempDir cleanup.

## How this fits together
Worktree from `origin/master`. Stub PR #6 is the durable card. Implement split is green; remaining phases are code review, usage docs, archive, ready title.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |

## Before merge
- [ ] Code review, usage docs, archive the OpenSpec change
- [ ] Drop the 🚧 stub title
- [x] CI succeeded on `a72cb8c`

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
| Specs in this PR | 4 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | a72cb8c374fa227d27503352c19886bbe5888d91 | Card must match the branch you measured |

### Stored data model
Redis cache keys are now prefixed with the connection identity hex when redis is enabled. Memory mode is a private map per Client (not a process dump). No migration of existing Redis keys — two Connections that previously shared keys now isolate.

### Technical review
Best possible solution: Copy `pkg/reclaim`; store CrowdsecConnection as the incarnation keyed by connection fields; Bouncer is ForRoute. Isolated cache so two backends cannot share remediations.

Do we have a high-confidence way to reproduce? Yes — two httptest LAPIs in `plugin_test.go`; mock e2e `dual-bouncer`.

Is this the best way to solve the issue? Yes vs `master`: connection-field key (not middleware name) so same LAPI shares one ticker and two LAPIs stay isolated.

### Evidence
What I checked:
- `go test` on new packages and plugin tests (Windows logging TempDir still fails as on master)
- GitHub check runs on `a72cb8c` all success

### Rank-up moves
None.
