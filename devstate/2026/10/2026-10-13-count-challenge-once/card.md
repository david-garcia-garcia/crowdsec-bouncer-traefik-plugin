## Motivation
CrowdSec 1.8 bot detection answers a suspicious request with a JavaScript challenge page. The page then calls back to URLs under `/crowdsec-internal/challenge/`: it loads `fpscanner.js` and `pow-worker.js`, and POSTs the proof to `/crowdsec-internal/challenge/submit`. Those calls go through the bouncer middleware and AppSec answers them.

Two problems sit on that one prefix.

1. Usage metrics over-count. Every relayed AppSec envelope was recorded as a dropped request (and dropped bytes). A single visitor solving one challenge therefore counted as several drops: the challenge page plus each script and the submit. A throwaway test moved the count from 1 to 2 for one solve. The reported drop numbers then overstate how many requests were actually blocked. Upstream describes this as point 5 of https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403; the patch was not copied.
2. Unanswered challenge paths reached origin. When AppSec is in use and nothing answered a request under the prefix (AppSec allow or an empty 200, a failure-action passthrough, or a cleared captcha gate), the request was forwarded to the origin application. For example `/crowdsec-internal/challenge/custom.js`, when no custom script is configured, was served by the backend. The challenge namespace belongs to CrowdSec, so it should not leak to or depend on origin. This was folded in from PR 196 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/196) at the owner's request on 2026-11-15; upstream describes it as point 4 of PR 403, and that patch was not copied either. The README also implied the prefix was safe whenever the middleware covered the host.

Priority: P2 — operators see inflated drop metrics, and unanswered challenge paths reach origin, with limited blast radius and no data loss.

## Implementation
Both parts act on the same prefix and share one helper, `isCrowdsecChallengeCallbackPath`, backed by the constant `crowdsecChallengeCallbackPrefix` in `pkg/bouncer/bouncer.go`. Merging the two parts replaced two duplicate path checks with this single owner.

- Metrics: the AppSec relay (`handleAppsecResponseServeHTTP`) still writes the envelope as before but skips `recordDropped` when the request path is under the prefix, so neither the request series nor the byte series moves. The challenge page itself, bans, captcha and non-challenge relays are counted as today. The metrics POST shape is unchanged.
- Termination: `serveAppSec` now wraps the previous logic (moved into `answerAppSec`). If nothing wrote a response, AppSec is in use for the request (subscribed, not skipped by a rule) and the path is under the prefix, it writes 404 and returns true, so `next` is not called. A real challenge, captcha or ban envelope is still written first. Paths outside the prefix are unchanged.
- README bot-detection sentence and the specs `core_plugin_appsec_bot-detection` and `core_plugin_appsec_failure-action` were updated, with devdocs. Regression tests cover dropped counts (page counted once, submit not counted, requests and bytes) and the 404 cases (AppSec allow, unpublished passthrough, captcha-form POST, solved captcha rule).

## What this changes
**Operators.** The usage-metrics dropped counters no longer grow for relays under `/crowdsec-internal/challenge/`, so one solved challenge counts once; no new settings.
**Admin users.** None.
**Developers.** Under `/crowdsec-internal/challenge/` the bouncer treats AppSec as the only owner: an unanswered request gets 404 and never calls `next`, and a relay there is not a drop; the shared helper `isCrowdsecChallengeCallbackPath` holds that rule.
**End users.** A request to a challenge-prefix path that nothing answers (such as an unconfigured `custom.js`) now gets 404 instead of whatever the origin application returns; the challenge itself behaves as before.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — operators see inflated drop metrics, and unanswered challenge paths reach origin, with limited blast radius and no data loss.
Reviewed head: 91ea457f
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43748976777 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-count-challenge-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197 | pr-host |
| CI | build 43748976777 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43748976777 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43748976777 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-count-challenge-drop-once/proposal.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-terminate-unanswered-challenge-paths/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-terminate-unanswered-challenge-paths/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-count-challenge-once on branch 2026-10-13-count-challenge-once targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197; CI build 43748976777 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43748976777.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which request path field implements the challenge-callback prefix? | additive asked — Desired names the path prefix; httprule already matches URL.Path (1 family in pkg/httprule, enumerated with pkg/bouncer/bouncer.go) | assumed — use req.URL.Path with strings.HasPrefix and /crowdsec-internal/challenge/. Traefik ServeHTTP fills URL.Path; do not parse RequestURI. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/2026/10/2026-10-13-count-challenge-once/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 5 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 91ea457f2caba7b756c14d6ec145ffbe08a10ffa | Card must match the branch you measured |

### Stored data model
None.
