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
Reviewed head: 1910881b
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
| Branch | 2026-11-14-appsec-unknown-length-body pushed | `git` |
| OpenSpec | appsec-inspect-unknown-length-body | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/204 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_body-read-timeout](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-unknown-length-body/openspec/changes/appsec-inspect-unknown-length-body/proposal.md) — added
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-unknown-length-body/openspec/changes/appsec-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-unknown-length-body/openspec/changes/appsec-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-unknown-length-body/openspec/changes/appsec-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-appsec-unknown-length-body/openspec/changes/appsec-inspect-unknown-length-body/proposal.md) — modified


## Deviations from the ask
- taken: a total read deadline on bodies of unknown length that blocks independently of `bouncerAppsecFailureAction` (decisions 1 and 2); no criterion names a `Query` signature change. → `Query` gains a parameter carrying the `http.ResponseController` the bouncer builds from its `rw`, so the deadline timer can cut an HTTP/1.1 read (`Body.Close` cannot, measured). 1 production call site (`pkg/bouncer/bouncer.go:458`) and 43 test call sites in `pkg/appsec` migrate in this change. — `pkg/appsec/query.go (Client.Query); pkg/bouncer/bouncer.go (applyAppsecServeHTTP, sole owner of rw)` — the response writer is the only handle that sets a read deadline on HTTP/1.1 and HTTP/2; the bouncer owns it, the AppSec client owns the read. Rank `bounded incidental` (explore.md, open question on distinguishing the deadline from a client disconnect).. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-appsec-unknown-length-body on branch 2026-11-14-appsec-unknown-length-body targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/204; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Does the deadline also bound HTTP/1.1 chunked bodies and slow bodies with a declared `Content-Length`? | bounded asked — changes existing `newAppsecBodyRequest` (1 caller, `newAppsecForwardRequest`; roots `pkg/**`); decision 1 "Bodies of unknown length are read and inspected like any other body, capped at `appsecBodyLimit`, with a total read deadline" | assumed — the deadline applies to every forwarded body whose length is unknown (`ContentLength < 0`), on every protocol, HTTP/1.1 chunked included: the protocol a client picks must not change how long the plugin waits (principle line). It does not apply to bodies with a declared `Content-Length`: there the client signal cannot reduce inspection today — a stalled body ends at Traefik `readTimeout` with `os.ErrDeadlineExceeded` → `appsecQuery:GetBody` → ban (measured error type), or the client disconnects (no origin call) — so a deadline there would only add failures for slow legitimate uploads. The deadline covers reading up to `appsecBodyLimit` bytes; once the limit is reached the read stops and the rest streams on uninspected (decision 5) with no plugin deadline. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 4 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 1910881b18898b41080a3bebcdfeeda481f5ac20 | Card must match the branch you measured |

### Stored data model
None.
