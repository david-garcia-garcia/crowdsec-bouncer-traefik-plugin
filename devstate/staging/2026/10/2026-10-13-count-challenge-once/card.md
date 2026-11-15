## Motivation
A visitor who solves a CrowdSec 1.8 bot-detection challenge sends several requests that the plugin relays from AppSec: the challenge page, `/crowdsec-internal/challenge/fpscanner.js`, `/crowdsec-internal/challenge/pow-worker.js`, and a POST to `/crowdsec-internal/challenge/submit`. Before this change each relayed envelope was counted as a drop in the usage metrics, so one solve was reported as several blocked requests (an explore run with a throwaway test saw the count go from 1 to 2). The live bot-detection spec also required `blockedRequests` to increment on every relay, with no exception.

The effect is inflated `blockedRequests` and dropped-bytes figures for any deployment using bot-detection challenges. Upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 5 describes the same need: count the challenge page once and skip the internal scripts and submit. This change does not copy that patch.

Priority: P3 — usage-metric counting is inflated and the spec is wrong, with no data loss or unsafe behaviour

## Implementation
`handleAppsecResponseServeHTTP` in `pkg/bouncer/bouncer.go` now skips `recordDropped` when the request path starts with the new constant `/crowdsec-internal/challenge/` (helper `isCrowdsecChallengeCallbackPath`). Any other path, including the challenge page itself, is still counted once with origin `appsec`. Bans, plugin captcha and other AppSec relays are untouched, and no labels or metrics POST shape changed. A regression test relays the same challenge envelope on `/protected` (expects 1 request and bytes > 0) and on `/crowdsec-internal/challenge/submit` (expects 0 requests and 0 bytes), read through `TestDroppedCount` and `TestDroppedByteCount`.

Master was merged in at a192cb60 (it brought #191, #194, #198, #201, #206, #207, #208, #209). The only conflict was in `pkg/bouncer/bouncer.go`, where both sides added a const and master renamed the literal "appsec" to `originAppsec`; the resolution keeps both and the skip path uses `originAppsec`. The OpenSpec delta (`count-challenge-drop-once`) was rebuilt on master's post-#206 requirement text, so archiving it does not revert #206. Locally, `go test ./...` and `golangci-lint` passed after the merge.

## What this changes
**Operators.** Usage-metric `blockedRequests` and dropped bytes for AppSec bot-detection no longer include the `/crowdsec-internal/challenge/` scripts and submit, so a solve counts once; no config change.
**Admin users.** None.
**Developers.** The bot-detection spec now exempts relays under `/crowdsec-internal/challenge/` from the `blockedRequests` increment; the exemption applies to any AppSec envelope on that path prefix.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P3 — usage-metric counting is inflated and the spec is wrong, with no data loss or unsafe behaviour
Reviewed head: 1d1474ff
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43744838085 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-count-challenge-once pushed | `git` |
| OpenSpec | count-challenge-drop-once | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197 | pr-host |
| CI | build 43744838085 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43744838085 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43744838085 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/changes/archive/2026-11-15-count-challenge-drop-once/proposal.md) — modified

Completed:
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-count-challenge-once on branch 2026-10-13-count-challenge-once targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/197; CI build 43744838085 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43744838085.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which request path field implements the challenge-callback prefix? | additive asked — Desired names the path prefix; httprule already matches URL.Path (1 family in pkg/httprule, enumerated with pkg/bouncer/bouncer.go) | assumed — use req.URL.Path with strings.HasPrefix and /crowdsec-internal/challenge/. Traefik ServeHTTP fills URL.Path; do not parse RequestURI. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_security.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-count-challenge-once/devstate/staging/2026/10/2026-10-13-count-challenge-once/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 1d1474ff3b85c4cb019c02bec43631a1d7530b2a | Card must match the branch you measured |

### Stored data model
None.
