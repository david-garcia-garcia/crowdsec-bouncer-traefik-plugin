## Motivation
A LAPI or blocklist decision whose type is neither ban nor captcha is skipped at ingest. Stream Put, Range upsert, and live/none query then treat the client as clean. Type challenge is the CrowdSec case that carries nothing to render; type allow and any other unknown type take the same skip. lua-cs-bouncer fails those types closed to ban. Leaving the skip in place lets an IP with an active unknown decision through.

Priority: P1 — unknown LAPI types fail open today

## Implementation
LAPI ingest maps ban and captcha through RemediationValue and stores every other type as ban, TRACE-logging handleStreamCache:unknownType via logger.Trace. streamPutItem, Range upsert, strongestLiveDecision, and queryLiveDecisions share that helper. RemediationValue stays empty so origin remap still treats empty as not a code. Same job as upstream https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403 point 1; this fork applies it at LAPI ingest because master has no root bouncer.go.

## What this changes
**Operators.** Unknown LAPI decision types (challenge, allow, anything else) now ban instead of allowing the IP. The unknown-type log is TRACE, not Info.
**Admin users.** None.
**Developers.** LAPI ingest stores unknown types as ban; RemediationValue still returns empty for those types.
**End users.** A client with only an unknown-type LAPI decision is banned instead of allowed.

## Merge readiness
In progress. 0 items remain.

Priority: P1 — unknown LAPI types fail open today
Reviewed head: 766ed786
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463159991 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-ban-unknown-lapi-types pushed | `git` |
| OpenSpec | ban-unknown-lapi-types | `openspec/` |
| Pull request | none | pr-host |
| CI | build 38463159991 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463159991 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463159991 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/openspec/changes/ban-unknown-lapi-types/proposal.md) — modified
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/openspec/changes/ban-unknown-lapi-types/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-ban-unknown-lapi-types on branch 2026-10-13-ban-unknown-lapi-types targeting master; PR no PR yet; CI build 38463159991 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38463159991.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should stream Range upserts map unknown types to ban, not only streamPutItem? | bounded asked — 1 Range call site in pkg/lapi/client_stream.go plus 3 other ingest sites in pkg/lapi (roots: pkg/); Desired names stream store and apply | assumed — include Range in the ingest helper; still not RemediationValue. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-ban-unknown-lapi-types/devstate/2026/10/2026-10-13-ban-unknown-lapi-types/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 766ed786178c533c6b3c9df7ca28b96f319baa12 | Card must match the branch you measured |

### Stored data model
- DecisionStore (memory and Redis): stream and live ingest now Put kind ban (	) for unknown LAPI types on existing Ip/header keys and Range 
ange-index lines. KindOriginString format is unchanged. No schema or field added or removed.
