## Motivation
Stream ingest stored a LAPI decision whose type was neither `ban` nor `captcha` (for example `challenge`) as an empty cache payload. Cache Get treats empty as a miss. A healthy stream then allowed the IP.

Live and none returned that empty payload on the first query (already remediates as a ban) and cached a miss, so the next Get repeated the LAPI call. CrowdSec's challenge protocol and lua-cs-bouncer fail closed to ban for unsupported types. Leaving stream allow is a wrong public contract for those IPs.

Priority: P1 — production serves a wrong public contract today

## Implementation
Both ingest switches call `lapiDecisionRemediation`, which maps `ban` and `captcha` to their cache payloads and maps every other type to `cache.BannedValue` after the existing `handleStreamCache:unknownType` Info log. Empty lists and JSON `null` stay `cache.NoBannedValue`. Tests assert stream Get and live cache for `challenge`/`allow`, and an empty live list still allowed.

CI Yaegi checkout is the go.mod module path (`github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`) with vendor packages copied onto GOPATH/src, so this fork can load `pkg/cache`. Dest `main` already failed that check.

## What this changes
**Operators.** A `challenge` or other unknown LAPI/blocklist decision now bans the IP in stream, live, and none.
**Admin users.** None.
**Developers.** Ingest unknown types store `cache.BannedValue`; Yaegi CI checkouts at the Go module path.
**End users.** An IP with an unknown LAPI type is banned instead of allowed in stream mode.

## Merge readiness
Ready for review. 0 items remain.

Priority: P1 — production serves a wrong public contract today
Reviewed head: 4d5c3d94
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38445767472 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-13-lapi-unknown-type-ban pushed | `git` |
| OpenSpec | ban-unknown-lapi-decision-types | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193 | pr-host |
| CI | build 38445767472 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38445767472 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38445767472 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-lapi-unknown-type-ban on branch 2026-10-13-lapi-unknown-type-ban targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/193; CI build 38445767472 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38445767472.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should unknown LAPI types be stored as `cache.BannedValue` at both ingest switches, including live which already remediates an empty return as a ban? | bounded asked — 2 existing switches in `bouncer.go` (roots searched: `bouncer.go`); Desired: stored and applied as a ban in stream and live | assumed — yes; set `cache.BannedValue` in both `default` branches so stream Get and live cache hits stay bans. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-lapi-unknown-type-ban/devstate/2026/10/2026-10-13-lapi-unknown-type-ban/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 4d5c3d94026c09ba74ec60e9a056b7da3389ffca | Card must match the branch you measured |

### Stored data model
- Redis cache (when Redis cache is enabled): unknown LAPI decision keys now persist payload `t` (ban) instead of an empty string. Same key, same TTL. No schema or field change. Memory cache is process-local.
