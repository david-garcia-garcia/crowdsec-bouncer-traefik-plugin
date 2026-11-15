## Motivation
AppSec challenge callbacks live under `/crowdsec-internal/challenge/`. CrowdSec's protocol forwards that prefix to AppSec and never to origin. On this plugin, `applyAppsecServeHTTP` returns false on allow (including `/crowdsec-internal/challenge/custom.js` when AppSec has no custom script) and on failure-action passthrough. `ServeHTTP` then calls `next`, so a host-wide middleware still leaks the prefix to origin.

Leaving it leaks CrowdSec-internal URLs and origin responses for paths that must stay inside AppSec. Reported as point 4 of https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403.

Priority: P1 — challenge callbacks leak to origin today

## Implementation
`serveAppSec` keeps captcha-rule fallthrough and SkipAppsec as they were. After a subscribed AppSec check that did not write, a path under `/crowdsec-internal/challenge/` is `http.NotFound` and true, so `ServeHTTP` does not call `next`. Relay, captcha, and ban still return true from `applyAppsecServeHTTP` first. Paths outside the prefix still call `next` on allow.

## What this changes
**Operators.** Unanswered `/crowdsec-internal/challenge/` is 404 instead of origin when AppSec is enabled. A path-limited middleware still needs a `PathPrefix(/crowdsec-internal/challenge)` router so AppSec sees the callbacks.
**Admin users.** None.
**Developers.** `serveAppSec` 404s unanswered AppSec results on `/crowdsec-internal/challenge/` and does not call `next`.
**End users.** A browser that hits an AppSec-unanswered challenge asset gets 404 instead of the origin page.

## Merge readiness
Ready for review. 0 items remain.

Priority: P1 — challenge callbacks leak to origin today
Reviewed head: ca743b47
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463644378 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-terminate-challenge-paths pushed | `git` |
| OpenSpec | terminate-unanswered-challenge-paths | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/196 | pr-host |
| CI | build 38463644378 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463644378 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463644378 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/openspec/changes/terminate-unanswered-challenge-paths/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/openspec/changes/terminate-unanswered-challenge-paths/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-terminate-challenge-paths on branch 2026-10-13-terminate-challenge-paths targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/196; CI build 38463644378 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463644378.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does the prefix include exact `/crowdsec-internal/challenge` with no trailing slash? | additive asked — new membership test this change adds; Desired names `/crowdsec-internal/challenge/` | assumed — `strings.HasPrefix(path, "/crowdsec-internal/challenge/")` as written. The regression path is `custom.js` under that slash. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-terminate-challenge-paths/devstate/2026/10/2026-10-13-terminate-challenge-paths/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | ca743b475cf2add5cde2a2c0d8c9cac301bbc77d | Card must match the branch you measured |

### Stored data model
None.
