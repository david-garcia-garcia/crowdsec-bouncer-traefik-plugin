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
Ready for review. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 90c63309
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36160028698 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-25-request-bypass-rules pushed | `git` |
| OpenSpec | request-bypass-rules | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/163 | pr-host |
| CI | build 36160028698 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36160028698 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36160028698 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/openspec/changes/request-bypass-rules/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-25-request-bypass-rules/openspec/changes/request-bypass-rules/proposal.md) — modified


## Deviations from the ask
- taken: method is a case-insensitive HTTP method token; a block with no path, no headers, and no cookies (method-only or nothing) fails plugin construction. → method is unanchored Go RE2 on `req.Method` with optional leading `!`; no silent case-fold and no forced `(?i)`. A method-only rule is valid. Construction fails only when path, headers, and cookies are absent AND method is any (omitted, empty, or a match-everything pattern such as `.*`). — `pkg/httprule` — honouring an exact case-insensitive token would add a second match family beside path RE2; treating a set method predicate as fully empty would reject `method: ^OPTIONS$`. Human correction already resolved method as RE2 same family as path.. Requester: confirmed.


## Follow-up issues
None.

## How this fits together
Ticket 2026-09-25-request-bypass-rules on branch 2026-09-25-request-bypass-rules targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/163; CI build 36160028698 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/36160028698.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where does the matcher package live under pkg/? | additive asked — new package this change creates; criterion Implement the matcher as its own package | assumed — pkg/httprule. Authoring type Rule with json method, path, headers, cookies. Compiled Set. No imports of this plugin. | explore |


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
| Reviewed head | 90c63309dd1e169266a7e37d586c510a49629ef8 | Card must match the branch you measured |

### Stored data model
None.
