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
Reviewed head: 943b8dfa
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
| Branch | 2026-09-30-origin-scheme pushed | `git` |
| OpenSpec | origin-scheme | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/177 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: one real end-to-end test forges TLS on/off and `X-Forwarded-Proto` and asserts Secure on `crowdsec_captcha_gate` and `__crowdsec_challenge`. → one Go httptest through the plugin with a stub AppSec that sets `__crowdsec_challenge` Secure iff the forwarded URI scheme is `https`. — `pkg/bouncer httptest (zzz_bouncer_test.go testBouncerWithAppsec) and pkg/captcha gate tests` — honouring "real" would add an HTTPS Traefik entrypoint to compose that is HTTP `:80` only; mocklapi does not implement CrowdSec's scheme check. The job (both cookies' Secure under TLS and proto) survives on the existing plugin test harness.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-30-origin-scheme on branch 2026-09-30-origin-scheme targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/177; CI not seen.

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
| Reviewed head | 943b8dfa48aa83af4a1d9be907d80fc46b068516 | Card must match the branch you measured |

### Stored data model
None.
