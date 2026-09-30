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
Reviewed head: 2fa78eda
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
| Branch | 2026-09-30-origin-scheme pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/177 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-30-origin-scheme on branch 2026-09-30-origin-scheme targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/177; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Who already owns client HTTPS / Host / the trust hop for proto? | bounded asked — existing Traefik proto contract and GetRemoteIP address owner, enumerated (research packet + `pkg/ip`); criterion 2 names the scheme rule and forbids hop re-check | assumed — Traefik entrypoint `forwardedHeaders` owns whether `X-Forwarded-Proto` is trustworthy. `Request.TLS` owns connection TLS to Traefik. `pkg/ip.GetRemoteIP` owns client address. `Request.Host` owns Host. The new constructor owns the scheme **token** derived from proto-then-TLS. AppSec URI host reuses `Request.Host` when `URL.Host` is empty. Do not re-derive hop trust in captcha or AppSec. | explore |


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
| Reviewed head | 2fa78eda1cc03077fb37c8b4bff165a8e450fa4f | Card must match the branch you measured |

### Stored data model
None.
