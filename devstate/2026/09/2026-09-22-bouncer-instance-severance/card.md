## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
Needs changes. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: 0a9e4c6e
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 2/6 | Needs work |
| CI proof | 2/6 | failed |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-22-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | none | pr-host |
| CI | build 35726475154 failed https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35726475154 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35726475154 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added

## Deviations from the ask
- taken:  →  — `` — requirement F3 / T2 subscriber sketch set `crowdsecLapiEnabled: true` with no key, which `ValidateParams` rejects because a true owner flag must Open. Built: `enabled: true`, owner flags false, instance names set (Open-vs-subscribe table).. Requester: not asked.

## Follow-up issues
- [ ] [Stream startup block still means more than "published"](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/knowledge/debt/2026-09-22-stream-startup-block-rethink.md) — `streamStartupBlock` still names stream startup while ready means subscribed client published.

## How this fits together
Ticket 2026-09-22-bouncer-instance-severance on branch 2026-09-22-bouncer-instance-severance targeting master; PR no PR yet; CI build 35726475154 failed https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35726475154.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which package owns the dual LAPI/AppSec slot tables and Publish/Subscribe API? | additive asked — new subsystem in scope (“Named LAPI and AppSec slots”, Late bind); criterion names publish/subscribe | assumed — `pkg/instance` owns both slot tables and Publish/Subscribe/Clear; `plugin.go` orchestrates only; tests colocated under that package. | implement |

## Before merge
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 6 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 0a9e4c6e11478e8573a61b3d5526e099bec543ef | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 0a9e4c6e11478e8573a61b3d5526e099bec543ef)

### Rank-up moves
None.
