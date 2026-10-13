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
Reviewed head: 99fd6fd0
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
| Branch | 2026-10-13-appsec-unexpected-status pushed | `git` |
| OpenSpec | appsec-unexpected-status-failure-action | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/191 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/changes/appsec-unexpected-status-failure-action/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/changes/appsec-unexpected-status-failure-action/proposal.md) — modified


## Deviations from the ask
- taken: a status that is not 200, not 502/503/504, and not a parseable JSON action follows `bouncerAppsecFailureAction` (so a bare 403 would passthrough when configured). → HTTP 403 with empty or invalid JSON keeps today's Query error, which the bouncer bans. 401 and other unexpected statuses follow FailureAction. — `pkg/appsec/query.go interpretAppsecBody` — the challenge protocol already owns 403 as the verdict channel and fail-closes empty/invalid JSON; honouring the letter would add a FailureAction branch on that channel.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-appsec-unexpected-status on branch 2026-10-13-appsec-unexpected-status targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/191; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does HTTP 403 with empty or invalid JSON follow FailureAction (ticket letter) or stay fail-closed ban (challenge protocol)? | bounded incidental — existing `interpretAppsecBody` 403 error path and `Test_appsecQuery_emptyForbiddenErrors` (1 Query call site, roots `pkg/appsec`); requirement Desired names unexpected statuses, not the 403 fail-closed rows | assumed — keep fail-closed ban on 403 empty/invalid JSON; 401 and other unexpected statuses use FailureAction | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 99fd6fd0a83297697aa5d045588e0fa65a226399 | Card must match the branch you measured |

### Stored data model
None.
