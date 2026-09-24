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
Reviewed head: 6d067b6e
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
| Branch | 2026-09-24-remediation-match-trace pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/152 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
- [ ] [Rename `std_go_logger_debug-attrs` to a Trace-named leaf](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-24-remediation-match-trace/knowledge/debt/2026-09-24-rename-std-go-logger-debug-attrs.md) — live spec and usage leaf still say `debug-attrs` while the unit is Request-path Trace.


## How this fits together
Ticket 2026-09-24-remediation-match-trace on branch 2026-09-24-remediation-match-trace targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/152; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Attribute names, and dump every present `RequestScopeValues` entry versus only the winning scope/value? | additive asked — new slog attributes on a remediating TRACE this change edits; Desired "values of scoped remediations in play (headers, AS, and the other mapped scopes)" | assumed — slog group `scopes` with each present `RequestScopeValues` key (CrowdSec scope name) and its header value. Omit missing headers. Do not add a separate winner field. | explore |


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
| Reviewed head | 6d067b6e552f716d6b7f62fb8533e25c0fc9a79c | Card must match the branch you measured |

### Stored data model
None.
