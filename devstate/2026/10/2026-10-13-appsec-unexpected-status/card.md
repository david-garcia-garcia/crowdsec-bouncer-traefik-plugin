## Motivation
CrowdSec AppSec answers HTTP 401 when the bouncer key is rejected, and also when AppSec cannot reach LAPI to validate a key it has not cached yet. The challenge protocol says that status, like 500, uses the component's configured AppSec failure behaviour.

This fork already mapped HTTP 500 and unreachable 502/503/504 onto `bouncerAppsecFailureAction`. A bare 401 still became Query error `appsecQuery statusCode:401`, and the bouncer banned the visitor at Debug regardless of passthrough. An AppSec restart during a LAPI outage therefore banned every client even when the operator set passthrough.

Priority: P2 — real operator pain with a limited blast radius (only AppSec 401/unexpected, default action remains ban)

## Implementation
Query still parses a JSON `action` first. After `interpretAppsecBody` errors, HTTP 403 stays fail-closed. Any other leftover status (401, 418, …) logs `appsecQuery:failure` at Error with attr `statusCode` and calls `resultForFailureAction`. Passthrough returns allow so the bouncer calls next; ban keeps `appsecQuery statusCode:<n>`; captcha returns `ErrFailureCaptcha`. 500 and 502/503/504 paths are untouched. Community PR 403's bool/default branch was not copied.

## What this changes
**Operators.** `bouncerAppsecFailureAction: passthrough` now allows the request when AppSec answers 401 or another unexpected status, instead of banning; watch Error `appsecQuery:failure` with `statusCode`.
**Admin users.** None.
**Developers.** Query treats 401/unexpected like 500 for FailureAction; empty 403 still errors; do not assume every non-200 is a ban.
**End users.** Visitors are no longer banned solely because AppSec returned 401 while the operator chose passthrough.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain with a limited blast radius (only AppSec 401/unexpected, default action remains ban)
Reviewed head: c3ed13f0
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38441837710 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-appsec-unexpected-status pushed | `git` |
| OpenSpec | appsec-unexpected-status-failure-action | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/191 | pr-host |
| CI | build 38441837710 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38441837710 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38441837710 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/changes/archive/2026-10-13-appsec-unexpected-status-failure-action/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/changes/archive/2026-10-13-appsec-unexpected-status-failure-action/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified


## Deviations from the ask
- taken: a status that is not 200, not 502/503/504, and not a parseable JSON action follows `bouncerAppsecFailureAction` (so a bare 403 would passthrough when configured). → HTTP 403 with empty or invalid JSON keeps today's Query error, which the bouncer bans. 401 and other unexpected statuses follow FailureAction. — `pkg/appsec/query.go interpretAppsecBody` — the challenge protocol already owns 403 as the verdict channel and fail-closes empty/invalid JSON; honouring the letter would add a FailureAction branch on that channel.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-appsec-unexpected-status on branch 2026-10-13-appsec-unexpected-status targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/191; CI build 38441837710 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38441837710.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does HTTP 403 with empty or invalid JSON follow FailureAction (ticket letter) or stay fail-closed ban (challenge protocol)? | bounded incidental — existing `interpretAppsecBody` 403 error path and `Test_appsecQuery_emptyForbiddenErrors` (1 Query call site, roots `pkg/appsec`); requirement Desired names unexpected statuses, not the 403 fail-closed rows | assumed — keep fail-closed ban on 403 empty/invalid JSON; 401 and other unexpected statuses use FailureAction | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-appsec-unexpected-status/devstate/2026/10/2026-10-13-appsec-unexpected-status/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c3ed13f0808e4df05c18be6b00b1e048a967df50 | Card must match the branch you measured |

### Stored data model
None.
