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
Reviewed head: 5a6d1240
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
| Branch | 2026-11-21-lapi-ban-retry-after pushed | `git` |
| OpenSpec | lapi-ban-retry-after | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/229 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_lapi_stream-apply](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/openspec/changes/lapi-ban-retry-after/proposal.md) — modified


## Deviations from the ask
- taken: decision 4 — "Range-scope bans carry no `Retry-After` in this change (the Range-index blob has no end)". → stream/alone Range bans (served from the Range-index blob) carry no header. In live/none, LAPI expands Range on the `?ip=` query and returns the decision with its `Duration`, so that ban carries `Retry-After` like any other LAPI ban answered 429. — `pkg/lapi/client_decisions.go (queryLiveDecisions parses the chosen decision's duration whatever its scope)` — decision 4's reason is the blob, which only stream/alone read. Following the letter in live/none would add a scope check to `queryLiveDecisions` only to hide an end it already knows.. Requester: not asked.


## Follow-up issues
- [ ] [`LookupRemediation` origin id is always 0](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-21-lapi-ban-retry-after/knowledge/debt/2026-11-21-lookup-remediation-origin-id-always-zero.md) — `Store.LookupRemediation` always returns origin id 0 although the catalog promises it; callers lean on the origin name.


## How this fits together
Ticket 2026-11-21-lapi-ban-retry-after on branch 2026-11-21-lapi-ban-retry-after targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/229; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does a LAPI captcha decision answered as a ban (unsubscribed captcha, unusable captcha client, remap, HEAD) carry `Retry-After`? | additive asked — passes an existing decision end to a branch that already exists; decision 7 names "unsubscribed captcha served as ban" | assumed — yes, when the status is 429. It is still a LAPI decision with a known end, and the response is a ban. This covers `handleCaptchaKindServeHTTP` downgrade reached from `serveLAPI` (unsubscribed or unusable client). The remap has no edge to ban (`pkg/configuration/origin_based_decision_remap.go:44`). A bypassCaptcha request that keeps a stored ban the remap would turn into a captcha keeps that ban's own end. HEAD: a usable captcha serves the challenge on HEAD (not a ban, no header). A HEAD ban carries the header with no body. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 5a6d1240525be688275ce06a1ba3800412a8d6de | Card must match the branch you measured |

### Stored data model
None.
