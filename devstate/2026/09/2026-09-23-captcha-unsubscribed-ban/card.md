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
In progress. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: 68cccfeb
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
| Branch | 2026-09-23-captcha-unsubscribed-ban pushed | `git` |
| OpenSpec | unsubscribed-captcha-ban-warn | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/openspec/changes/unsubscribed-captcha-ban-warn/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `handleRemediationServeHTTP`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/knowledge/debt/2026-09-23-rename-handle-remediation-serve-http.md) — `handleRemediationServeHTTP` hides that it owns captcha-kind serve vs ban.


## How this fits together
Ticket 2026-09-23-captcha-unsubscribed-ban on branch 2026-09-23-captcha-unsubscribed-ban targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Exact WARN message text? | additive asked — new log line this change creates; Unknowns Exact WARN message text | assumed — stem crowdsec bouncer captcha unsubscribed; attrs leg=captcha and instanceName (empty when unsubscribed); traefikName already on the logger from bouncer.New | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 68cccfeb000be8acbef14310957348e645b06f5c | Card must match the branch you measured |

### Stored data model
None.
