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
Reviewed head: b1279447
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
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `handleRemediationServeHTTP`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-captcha-unsubscribed-ban/knowledge/debt/2026-09-23-rename-handle-remediation-serve-http.md) — `handleRemediationServeHTTP` hides that it owns captcha-kind serve vs ban.


## How this fits together
Ticket 2026-09-23-captcha-unsubscribed-ban on branch 2026-09-23-captcha-unsubscribed-ban targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/139; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Exact WARN message text? | additive asked — new log line this change creates; Unknowns “Exact WARN message text”; Desired names a WARN that captcha could not be served due to a misconfiguration | assumed — stem `crowdsec bouncer captcha unsubscribed`, same family as `crowdsec bouncer backend missing` / `crowdsec bouncer stream scopes missing`. Attrs `leg=captcha` and `instanceName` (empty when unsubscribed). Logger already carries `traefikName` from `bouncer.New`. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b12794472ba4c0390a72a5b13c35ff4b7f983c4f | Card must match the branch you measured |

### Stored data model
None.
