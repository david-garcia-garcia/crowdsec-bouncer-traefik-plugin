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
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 6d379cfc
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-26-remediation-header-reasons pushed | `git` |
| OpenSpec | remediation-header-reasons | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/166 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/remediation-header-reasons/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-26-remediation-header-reasons/openspec/changes/remediation-header-reasons/proposal.md) — modified


## Deviations from the ask
- taken: Ground names `pkg/captcha/captcha.go` `writeRemediationHeader(..., "captcha")` on the challenge page, so captcha would have to know `captcha:lapi[:origin]` / `captcha:decision-header` / failure reasons. → `ServeHTTP` takes the already-formatted challenge-page value from the Bouncer; captcha only writes `captcha:solved` on Pass 302 and `WriteSolvedRedirect`. — `pkg/captcha/captcha.go writeRemediationHeader` — honouring captcha-owned origin mapping would add `MetricsOrigin` / `OriginPlugin*` to a Client whose job is widget and verify; the header name was already lifted off Client for that reason (`core_plugin_middleware_bouncer`).. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-26-remediation-header-reasons on branch 2026-09-26-remediation-header-reasons targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/166; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where should the emit helper live? | additive asked — Unknowns names helper location; Desired requires structured values at the existing writers | assumed — unexported formatRemediationHeader in pkg/bouncer/remediation_header.go; ban, AppSec, and disconnect call it; captcha does not import the table | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 6d379cfc70a910bb1b532616b9d4f09ba2af96ff | Card must match the branch you measured |

### Stored data model
None.
