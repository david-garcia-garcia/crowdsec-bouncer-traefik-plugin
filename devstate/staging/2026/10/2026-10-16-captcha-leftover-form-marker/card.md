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
Reviewed head: 12ceda00
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
| Branch | 2026-10-16-captcha-leftover-form-marker pushed | `git` |
| OpenSpec | captcha-challenge-form-marker | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/201 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/openspec/changes/captcha-challenge-form-marker/proposal.md) — modified
- [core_plugin_middleware_captcha-widget](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-16-captcha-leftover-form-marker/openspec/changes/captcha-challenge-form-marker/proposal.md) — modified


## Deviations from the ask
- taken: leftover detection is POST contains `crowdsec_captcha_challenge=v1`, with no size named. → leftover detection keeps the existing 64KiB peek; over-cap bodies are not leftover forms. — `pkg/captcha/form.go (captchaFormMaxBytes, peekCaptchaFormBody)` — honouring an uncapped read would drop the live routing promise that detection never costs origin its body; the ask's HTML does not name dropping the cap.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-16-captcha-leftover-form-marker on branch 2026-10-16-captcha-leftover-form-marker targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/201; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| After the gate is valid, does leftover-form detection read only crowdsec_captcha_challenge=v1, not TokenField? | bounded asked — existing IsCaptchaFormPost has 1 production caller in pkg/bouncer/bouncer.go handleCaptchaKindServeHTTP, searched Go files; requirement Proposed solution valid-gate branch names marker-only detection | assumed — change IsCaptchaFormPost to that marker; migrate the bouncer caller (signature stays) and the routing tests in pkg/captcha and pkg/bouncer. | explore |


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
| Reviewed head | 12ceda00d633eb93b7fbc3ded78d6a536cb4569f | Card must match the branch you measured |

### Stored data model
None.
