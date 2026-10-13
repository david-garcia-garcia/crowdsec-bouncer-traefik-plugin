Developer review: ready for review — 2026-09-05T09:14:00.108Z

## What this changes
**Operators.** Two Crowdsec bouncer middlewares in one Traefik now keep isolated LAPI streams and caches. Same connection fields still share one backend; different LAPI/mode/redis/interval are two live backends. After Traefik drops the last holder and grace elapses, `CrowdsecConnection.Close()` stops tickers, idle LAPI/AppSec HTTP, and the Redis idle pool. Watch debug lines `reclaim_put|bind|orphan|reclaim|dispose`.

**Admin users.** None.

**Developers.** Root `plugin.go` `New` reclaims `*crowdsecconnection.CrowdsecConnection` by connection-field hash and returns `pkg/bouncer`. `SimpleRedis.Close` / `cache.Client.Close` drain idle Redis sockets; Connection dispose calls them. Usage packets: `core_plugin_middleware`, `std_go_reclaim`, `core_cache_client`, `build_e2e_mock`. Redis keys use identity prefix. Mock e2e `dual-bouncer` covers two middlewares / two LAPIs.

**End users.** A client IP can be banned on one Crowdsec backend and allowed on another in the same Traefik process.

## Motivation
On `master`, stream ticker, decision cache, and LAPI health are process globals, so a second Crowdsec bouncer config in the same Traefik is first-wins. Operators cannot run two backends or compare configs side-by-side. Without this change that sharing stays the product.

## Merge readiness
OpenSpec change is archived, PR title is ready, and CI succeeded on `f7f9ba0`. 0 items remain.

Priority: P2 — operators cannot run two Crowdsec configs in one Traefik; workaround is a second Traefik
Reviewed head: f7f9ba0
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Required checks succeeded on the ready head |
| CI proof | 6/6 | All three required checks succeeded on `f7f9ba0` |
| Local tests proof | N/A | Remote PR; CI covers it |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-core-plugin-lifetime-refactor pushed | `git` `f7f9ba024d6559f91996d372ce7b77b21ed06ee9` |
| OpenSpec | crowdsec-connection-bouncer-split (archived) | `openspec/changes/archive/2026-09-05-crowdsec-connection-bouncer-split/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/6 | GitHub PR list |
| CI | Main Process success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33957209171/job/101282593883 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33957209174/job/101282595044 ; e2e (docker + pester) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33957209174/job/101282595136 | GitHub check runs |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | GitHub PR comments |
| Security | None. | devstate/codereview.md |
| Performance | None. | devstate/codereview.md |

## Specs
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/archive/2026-09-05-crowdsec-connection-bouncer-split/proposal.md) — added
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/archive/2026-09-05-crowdsec-connection-bouncer-split/proposal.md) — added
- [std_go_reclaim_context-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/archive/2026-09-05-crowdsec-connection-bouncer-split/proposal.md) — added
- [build_e2e_mock_dual-bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-core-plugin-lifetime-refactor/openspec/changes/archive/2026-09-05-crowdsec-connection-bouncer-split/proposal.md) — added

## Follow-up issues
- [ ] [note] [large] `pkg/logger` never closes `OpenFile`; Windows logging tests fail TempDir cleanup.

## How this fits together
Worktree from `origin/master`. PR #6 is the durable card. The OpenSpec change is archived; CI on `f7f9ba0` succeeded.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Must CreateConfig/New stay in the module-root package? | assumed — yes; thin root to plugin.go | explore |
| Does captcha live on Connection or Bouncer? | assumed — Bouncer | explore |
| Does AppSec live on Connection or Bouncer? | assumed — Connection owns client+host; Bouncer calls on pass when that route has AppSec enabled | explore |
| Type spelling CrowdSecConnection vs CrowdsecConnection? | assumed — CrowdsecConnection / crowdsecconnection | explore |

## Before merge
None.

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
| Reviewed head | f7f9ba024d6559f91996d372ce7b77b21ed06ee9 | Card must match the branch you measured |

### Stored data model
Redis cache keys are now prefixed with the connection identity hex when redis is enabled. Memory mode is a private map per Client. No migration of existing Redis keys.

### Technical review
Best possible solution: Copy `pkg/reclaim`; store CrowdsecConnection as the incarnation keyed by connection fields; Bouncer is the per-router handler. Isolated cache so two backends cannot share remediations. Dispose drains that Connection’s Redis idle pool.

Do we have a high-confidence way to reproduce? Yes — two httptest LAPIs in `plugin_test.go`; mock e2e `dual-bouncer`; `TestCloseDrainsIdleAndDoesNotRepool`.

Is this the best way to solve the issue? Yes vs `master`: connection-field key so same LAPI shares one ticker and two LAPIs stay isolated.

### Evidence
What I checked:
- Four-axis review of `origin/master...HEAD`
- GitHub check runs on `f7f9ba0` all success (Main Process, e2e mock LAPI, e2e docker + pester)
- `pkg/simpleredis` Close drain test

### Rank-up moves
- Extract one `decisionRemediation` helper for the duplicated ban/captcha/default switch in stream vs live (judgement, not applied)
- Call `Close()` when `crowdsecconnection.New` fails after the struct exists
- Cancel in-flight stream/metrics HTTP on dispose
