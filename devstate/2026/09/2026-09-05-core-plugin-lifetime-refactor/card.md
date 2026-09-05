Developer review: in progress — 2026-09-05T08:33:14.680Z

## What this changes
**Operators.** Two Crowdsec bouncer middlewares in one Traefik now keep isolated LAPI streams and caches. Same connection fields still share one backend; different LAPI/mode/redis/interval are two live backends. Watch debug lines `reclaim_put|bind|orphan|reclaim|dispose`. Release workflows bump `crowdsecconnection.Version` in `pkg/crowdsecconnection/version.go`.

**Admin users.** None.

**Developers.** Root `plugin.go` `New` reclaims `*crowdsecconnection.CrowdsecConnection` by connection-field hash and returns `pkg/bouncer`. Usage packets: `core_plugin_middleware`, `std_go_reclaim`, `core_cache_client`, `build_e2e_mock`. Redis keys use identity prefix. Mock e2e `dual-bouncer` covers two middlewares / two LAPIs.

**End users.** A client IP can be banned on one Crowdsec backend and allowed on another in the same Traefik process.

## Motivation
On `master`, stream ticker, decision cache, and LAPI health are process globals, so a second Crowdsec bouncer config in the same Traefik is first-wins. Operators cannot run two backends or compare configs side-by-side. Without this change that sharing stays the product.

## Merge readiness
Usage docs landed on `37e8d20`. Archive and ready title remain. CI on this head is still running. 2 items remain.

Priority: P2 — operators cannot run two Crowdsec configs in one Traefik; workaround is a second Traefik
Reviewed head: 37e8d20
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI on the usage-docs head is still in progress |
| CI proof | 3/6 | All three required checks in progress on `37e8d20` |
| Local tests proof | N/A | Remote PR; CI covers it |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `37e8d20d1acf58099a7b387b4e131352bbbe1857` |
| OpenSpec | crowdsec-connection-bouncer-split | `openspec/changes/crowdsec-connection-bouncer-split/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33955550166/job/101278116632 ; e2e (binary + mock LAPI) in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33955550151/job/101278125125 ; e2e (docker + pester) in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33955550151/job/101278125274 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

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
Worktree from `origin/master`. Stub PR #6 is the durable card. Usage packets are on `37e8d20`; remaining work is archive and a ready title.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when that route has AppSec enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |

## Before merge
- [ ] Archive the OpenSpec change
- [ ] Drop the 🚧 stub title
- [ ] CI succeeded on `37e8d20`

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
| Reviewed head | 37e8d20d1acf58099a7b387b4e131352bbbe1857 | Card must match the branch you measured |

### Stored data model
Redis cache keys are now prefixed with the connection identity hex when redis is enabled. Memory mode is a private map per Client. No migration of existing Redis keys.

### Technical review
Best possible solution: Copy `pkg/reclaim`; store CrowdsecConnection as the incarnation keyed by connection fields; Bouncer is the per-router handler. Isolated cache so two backends cannot share remediations.

Do we have a high-confidence way to reproduce? Yes — two httptest LAPIs in `plugin_test.go`; mock e2e `dual-bouncer`.

Is this the best way to solve the issue? Yes vs `master`: connection-field key so same LAPI shares one ticker and two LAPIs stay isolated.

### Evidence
What I checked:
- knowledge/devdocs packets for plugin, reclaim, isolated cache, mock e2e
- GitHub check runs on `37e8d20` all in progress

### Rank-up moves
None.
