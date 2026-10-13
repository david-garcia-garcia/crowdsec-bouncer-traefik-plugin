## Motivation
Bot-detection posts the visitor proof to `/crowdsec-internal/challenge/submit`. AppSec must receive that form in full. This fork already forwards the whole readable body when `appsecBodyLimit` is `0`, and the default 10MB cap is meant to be enough.

The README AppSec / bot-detection paragraph and the **AppsecBodyLimit** key never said the challenge proof depends on that body. An operator who set a smaller positive limit, or who read upstream PR 403 and thought `0` sends no body, had no fork-accurate warning.

Left alone, a truncated proof keeps the visitor on the challenge. The gap is operator wording, not the copy path.

Priority: P3 — docs and operator clarity; no current runtime change

## Implementation
Two README seams now state the same facts: `/crowdsec-internal/challenge/submit` must reach AppSec with the full form; the default 10MB is enough; a smaller positive limit cuts the proof short; `0` means no limit and the whole body is sent. Runtime and `Test_appsecQuery_zeroBodyLimitForwardsPost` are unchanged. `skip_specs` — no live-contract delta.

## What this changes
**Operators.** README now says the challenge submit POST needs the full form, the default 10MB is enough, a smaller positive limit cuts the proof short, and `appsecBodyLimit` `0` sends the whole body.
**Admin users.** None.
**Developers.** None.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P3 — docs and operator clarity; no current runtime change
Reviewed head: 2e19fd72
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
| Branch | 2026-10-13-challenge-submit-body pushed | `git` |
| OpenSpec | document-challenge-submit-body | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/194 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-challenge-submit-body on branch 2026-10-13-challenge-submit-body targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/194; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does CrowdSec AppSec reject a truncated `/crowdsec-internal/challenge/submit` body and re-challenge forever? | additive asked — Desired names the forever-challenge consequence as the reason to document; no engine code moves | assumed — write the operator warning as asked; do not claim this run measured the engine. Research already says the POST body must be relayed; upstream PR 403 asserts reject-and-retry. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-submit-body/devstate/2026/10/2026-10-13-challenge-submit-body/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 2e19fd72a3cdccfa4c1472bec90a5ac534be60ce | Card must match the branch you measured |

### Stored data model
None.
