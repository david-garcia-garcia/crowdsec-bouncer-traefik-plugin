Developer review: in progress — 2026-09-05T13:40:55.310Z

IssueKey: 2026-09-05-add-fail-mode
JobName: 2026-09-05-add-fail-mode

## What this changes
**Operators.** Set `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` (`passthrough` | `ban` | `captcha`, default `ban`). The three AppSec block bools are gone; leftover `false` YAML is ignored — use `crowdsecAppsecFailureAction: passthrough`. Empty strings are rejected at ValidateParams.

**Admin users.** None.

**Developers.** `Config` gained the two Crowdsec-prefixed enums; live LAPI errors ban with `ReasonLAPI`; stream-unhealthy misses ban with `ReasonTECH`; `AppsecPolicy` is one failure action; challenge relay from #9 is unchanged.

**End users.** None.

## Motivation
On `master`, LAPI/AppSec unavailability is split across `updateMaxFailure`, live ban-on-error, and three AppSec booleans. Without the two actions, operators cannot set one fallback per backend.

## Merge readiness
Code review applied two spec fixes; CI is still running on the new head. 1 item remains.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: c2d6141
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply + review fixes landed; CI still in progress |
| CI proof | 3/6 | Main Process in progress; e2e queued/in progress |
| Local tests proof | N/A | Remote PR; CI is the proof axis |
| Review resolution | 6/6 | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-fail-mode pushed | git @ c2d6141 |
| OpenSpec | lapi-appsec-failure-action | openspec/changes/archive/2026-09-05-lapi-appsec-failure-action/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/10 | pr-host |
| CI | build 33969597623 in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33969597623 ; e2e 33969597637 in_progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33969597637 | get_check_runs |
| Local tests | passed | handoff.yaml; `go test ./pkg/configuration/ ./pkg/bouncer/` after review fixes |
| PR comments | no comments | get_comments empty at implement |
| Security | None. | destate/codereview.md |
| Performance | None. | destate/codereview.md |

## Specs
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/archive/2026-09-05-lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/archive/2026-09-05-lapi-appsec-failure-action/proposal.md) — added
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-add-fail-mode/openspec/changes/archive/2026-09-05-lapi-appsec-failure-action/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
Ticket on dest `master`. Stub PR 10. Review applied empty-reject and live `ReasonLAPI`. Devdocs impact next.

## Decision needed
None.

## Before merge
- [ ] Wait for CI on the apply

## Findings
- [P3] Empty failure-action strings were accepted — FIX — ValidateParams now rejects `""`. Path: `pkg/configuration/configuration.go`. Reply none.
- [P3] Live LAPI error ban used `ReasonTECH` — FIX — live path now uses `ReasonLAPI`. Path: `pkg/bouncer/bouncer.go`. Reply none.

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
| Reviewed head | c2d6141ee574052a1ba353295acf6d696e704f68 | Card must match the branch you measured |

### Stored data model
Public Traefik plugin config: `crowdsecLapiFailureAction` and `crowdsecAppsecFailureAction` strings; three AppSec block bools removed. Empty values rejected. Reclaim identity includes LAPI failure action. AppSec action is per-router on Bouncer.

### Technical review
Best possible solution: Crowdsec-prefixed enums plus keeping `UpdateMaxFailure` match dest `master` and the agreed public surface; challenge relay from #9 stays.

Do we have a high-confidence way to reproduce? Yes — unit tests on validate and bouncer failure dispatch.

Is this the best way to solve the issue? Yes for the agreed public surface.

### Evidence
What I checked:
- Four-axis review of `origin/master...HEAD` excluding destate/.cursor
- Spec hard findings applied in 5f427bf
- get_check_runs on PR 10 after that push: Main Process + e2e in progress/queued

### Rank-up moves
None.
