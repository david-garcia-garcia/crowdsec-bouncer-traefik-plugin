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
Reviewed head: edc013ac
Owner decision: None.

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
| Branch | 2026-11-23-backoff-action-per-leg pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: add `lapiUnhealthyBackOffPeriodSecs` to the LAPI session identity (`pkg/lapi/session.go`), like AppSec does in `pkg/appsec/session.go`. → add it to the LAPI `ownership` payload (`OwnershipKey`), only in `live` / `none`; `streamSession` / `SessionHex` stay unchanged. — `pkg/lapi/identity.go` — AppSec's identity is its Client Open key; the LAPI equivalent is `ownership`, which reclaims the `lapi.Client` that holds the gate. `SessionHex` keys the DecisionStore, so a cooldown change there would drop the cache and the stream cursor.. Requester: not asked.


## Follow-up issues
- [ ] [WAF failure-action captcha downgrade shows reason `LAPI`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/knowledge/debt/2026-11-23-waf-failure-captcha-downgrade-reason.md) — an AppSec or ModSec failure-action captcha that downgrades to a ban shows ban-template reason `LAPI`, because `handleRemediationServeHTTP` hard-codes `ReasonLAPI`.


## How this fits together
Ticket 2026-11-23-backoff-action-per-leg on branch 2026-11-23-backoff-action-per-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236; CI not seen.

## Explore Decisions
None.

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
| Reviewed head | edc013ac92b6b12d8bd261be6274a6f50b55f1ab | Card must match the branch you measured |

### Stored data model
None.
