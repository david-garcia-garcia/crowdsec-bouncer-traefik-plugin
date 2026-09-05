Developer review: in progress — 2026-09-05T13:36:17.897Z

IssueKey: 2026-09-05-add-fail-mode
JobName: 2026-09-05-add-fail-mode

## What this changes
**Operators.** Set `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`, default `ban`). The three AppSec block bools are gone; leftover `false` YAML is ignored — use `crowdsecAppsecFailureAction: passthrough`.

**Admin users.** None.

**Developers.** `Config` gained the two Crowdsec-prefixed enums; live LAPI errors and stream-unhealthy misses dispatch that action; `AppsecPolicy` is one failure action; challenge relay from #9 is unchanged.

**End users.** None.

## Motivation
On `master`, LAPI/AppSec unavailability is split across `updateMaxFailure`, live ban-on-error, and three AppSec booleans. Without the two actions, operators cannot set one fallback per backend.

## Merge readiness
Apply is on the branch; CI is still running. 1 item remains.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: e2fd465
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply landed; CI still in progress |
| CI proof | 3/6 | Main Process and both e2e jobs in progress |
| Local tests proof | N/A | Remote PR; CI is the proof axis |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-fail-mode pushed | git @ e2fd465 |
| OpenSpec | lapi-appsec-failure-action | openspec/changes/lapi-appsec-failure-action/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/10 | pr-host |
| CI | build 33969376331 in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33969376331 ; e2e 33969376364 in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33969376364 | get_check_runs |
| Local tests | passed | handoff.yaml; `go test ./pkg/...` |
| PR comments | no comments | get_comments / get_review_comments |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/lapi-appsec-failure-action/proposal.md) — modified

## Follow-up issues
- [ ] [note] [large] public `crowdsecAppsecFailureBlock` / `crowdsecAppsecUnreachableBlock` / `crowdsecAppsecUnreadableBodyBlock` → `crowdsecAppsecFailureAction`
- [ ] [note] [large] public `updateMaxFailure` vs new `crowdsecLapiFailureAction`

## How this fits together
Ticket on dest `master`. Stub PR 10. Apply `b50f987` / destate `e2fd465`. Human renamed keys to the Crowdsec prefix. Code review next.

## Decision needed
None.

## Before merge
- [ ] Wait for CI on the apply

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
| Specs in this PR | 2 added / 1 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e2fd4653effb4df675f68df531c45de18a41d07c | Card must match the branch you measured |

### Stored data model
Public Traefik plugin config: `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` strings; three AppSec block bools removed. Reclaim identity includes LAPI failure action. AppSec action is per-router on Bouncer.

### Technical review
Best possible solution: Crowdsec-prefixed enums plus keeping `UpdateMaxFailure` match dest `master` and the agreed public surface; challenge relay from #9 stays.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/configuration/ ./pkg/crowdsecconnection/ ./pkg/bouncer/` passed on the apply.

Is this the best way to solve the issue? Yes for the agreed public surface.

### Evidence
What I checked:
- `go test ./pkg/...` passed (e2fd465)
- get_check_runs on PR 10: Main Process + two e2e jobs in_progress
- Live LAPI HTTP error returns `""` plus error, not a ban value (`failure_action_test.go`)

### Rank-up moves
None.
