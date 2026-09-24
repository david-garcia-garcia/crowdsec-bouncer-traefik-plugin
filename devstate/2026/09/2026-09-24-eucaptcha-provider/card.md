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
Reviewed head: 174070cd
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
| Branch | 2026-09-24-eucaptcha-provider pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155 | pr-host |
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
Ticket 2026-09-24-eucaptcha-provider on branch 2026-09-24-eucaptcha-provider targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/155; CI not seen.
Upstream pull request (maxlerebourg tree, not this repo): https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/317

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Is an empty User-Agent a rejection the same way as an empty client address? | additive asked — new verifier this change creates; Unknowns on requirement.md; Desired names empty address as rejection only | assumed — no. Forward r.UserAgent() including empty string. Do not local-reject empty UA. Official field is necessary but the owner does not state HTTP for empty or missing UA. Empty client address stays a local reject on this verifier. Source knowledge/research/ext_eucaptcha_verify/. | explore |
| How is train encoded when absent vs explicit false vs JSON null? | additive asked — Desired names mint only when success is true and train is false or null | assumed — Pass-true only when success is true and train is JSON false or JSON null. Explicit true is Pass-false. Omitted key: Go pointer-to-bool cannot tell omit from null; treat nil as the false-or-null case (mint if success). Official examples always include train false or train true. Source knowledge/research/ext_eucaptcha_verify/. | explore |
| Should empty client address reject on every Pass implementer, or only eucaptcha? | additive asked — Desired names empty client address as a rejection; Affected Pass surface; siteverify live spec says omit remoteip when empty | assumed — eucaptcha verifier only. Siteverify and assessments keep omit-when-empty. Do not rewrite those specs for this ticket. | explore |


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
| Reviewed head | 174070cd2abc7afb4b7c5839610e7100b80a1eee | Card must match the branch you measured |

### Stored data model
None.
