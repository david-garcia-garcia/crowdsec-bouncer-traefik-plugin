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
Reviewed head: ec00b28b
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
| Branch | 2026-11-14-appsec-captcha-verdict pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/206 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: an AppSec `captcha` verdict is remediated as a captcha. → also route a POST carrying `crowdsec_captcha_challenge=v1` to the captcha gate when AppSec allowed it, so the form can be validated even when the operator's rule does not match the POST. — `pkg/bouncer/bouncer.go (serveAppSec), pkg/captcha/captcha.go (HasChallengeMarker)` — AppSec judges each request alone; without this, a rule that matches the GET but not the form POST forwards the solve to origin and the captcha can never be solved.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-appsec-captcha-verdict on branch 2026-11-14-appsec-captcha-verdict targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/206; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should an AppSec `captcha` verdict serve the router's configured captcha, or only the ban page (the review's minimal step)? | bounded asked — reverses requirement "AppSec captcha envelope is parsed and relayed" whose one caller (`applyAppsecServeHTTP`) and two locking tests were enumerated in `pkg/`; requirement.md Desired line 1 names remediating AppSec `captcha` as a captcha | assumed — serve the configured captcha through `handleCaptchaKindServeHTTP`; no usable captcha client → `ban:captcha-downgrade`. | explore |


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
| Reviewed head | ec00b28bde2022701a804891ffaa8ee9be986f7b | Card must match the branch you measured |

### Stored data model
None.
