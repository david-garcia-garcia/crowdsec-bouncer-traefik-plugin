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
Reviewed head: b00fafe6
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Limited confidence |
| CI proof | 3/6 | in progress |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-03-dropped-bytes pushed | `git` |
| OpenSpec | dropped-bytes | `openspec/` |
| Pull request | none | pr-host |
| CI | build 37097539128 in progress | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37097539128 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-03-dropped-bytes/openspec/changes/dropped-bytes/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-03-dropped-bytes on branch 2026-10-03-dropped-bytes targeting master; PR no PR yet; CI build 37097539128 in progress.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which labels does the new `dropped` / `byte` item send? | additive incidental — labels on an item this change creates; no In-scope or criterion line names those labels (Unknowns) | assumed — `origin` + `ip_type` only, same values as the paired request item; omit `remediation` (firewall `dropped` / `byte` shape in `ext_crowdsec_lapi_usage-metrics`) | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b00fafe66695fe450e12c41a899d4e78991e49dc | Card must match the branch you measured |

### Stored data model
None.
