## Motivation
AppSec Query already stamps the required extras on the outbound listener request: client IP, URI, host, verb, API key, and User-Agent. CrowdSec AppSec also expects the original client HTTP version on `X-Crowdsec-Appsec-Http-Version` as two ASCII digits (`10` for HTTP/1.0, `11` for HTTP/1.1, `20` for HTTP/2) so it can populate `r.Proto` for rule evaluation. Upstream reported the same gap: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400

That header is never sent. AppSec then skips `applyHTTPVersion` and keeps the listener connection proto, which is HTTP/1.1. An HTTP/2 or HTTP/1.0 client is therefore evaluated as HTTP/1.1.

Left alone, proto-aware AppSec rules cannot see the real client protocol behind the HTTP/1.1 forward. Blast radius is those rules only; CrowdSec treats a missing header as optional for old bouncers.

Priority: P2 — real operator, admin-user, or end-user pain, with a workaround or limited blast radius

## Implementation
`newAppsecForwardRequest` already holds the inbound request, so `ProtoMajor` and `ProtoMinor` are already on `req`. When `ProtoMajor` is greater than 0, it sets `X-Crowdsec-Appsec-Http-Version` to two ASCII digits, major then minor (`fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)`). HTTP/1.0 is `10`, HTTP/1.1 is `11`, HTTP/2 is `20`, HTTP/3 is `30`. When `ProtoMajor` is 0 the header is omitted so AppSec keeps the listener proto instead of applying `00`. The digits are read from those fields; `Request.Proto` is not parsed. A Query forward-capture test proves the encodings and the omit.

## What this changes
**Operators.** None.
**Admin users.** None.
**Developers.** None.
**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator, admin-user, or end-user pain, with a workaround or limited blast radius
Reviewed head: 7180cf7e
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
| Branch | 2026-10-07-appsec-http-version pushed | `git` |
| OpenSpec | appsec-http-version | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/openspec/changes/appsec-http-version/proposal.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-07-appsec-http-version on branch 2026-10-07-appsec-http-version targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189; CI not seen. OpenSpec change `appsec-http-version` folds `X-Crowdsec-Appsec-Http-Version` into `core_plugin_appsec_client`. Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400. Usage packet `core_plugin_appsec` already covers Query; GitHub PR summary was not updated.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should Query omit the header when `ProtoMajor` is 0 (upstream PR 400 guard)? | additive incidental - optional skip on `ProtoMajor` 0; requirement does not name the upstream `if httpReq.ProtoMajor > 0` guard | assumed - omit when `ProtoMajor` is 0 so AppSec keeps connection proto instead of applying ` "00" `. Real Traefik requests have `ProtoMajor` >= 1. | propose |
| How is HTTP/3 (`ProtoMajor` 3) encoded? | additive incidental - same two-digit encoding for `ProtoMajor` 3; Desired names ` "10" ` / ` "11" ` / ` "20" ` only | assumed - `fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)` so HTTP/3 is ` "30" `. `applyHTTPVersion` accepts any two digits (`r.Proto` becomes `HTTP/3.0`). This plugin already inspects `ProtoMajor` >= 2 including 3 in `isBodyUnreadable`. | propose |

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-07-appsec-http-version/devstate/2026/10/2026-10-07-appsec-http-version/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 1 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7180cf7ee7749e906c11ffbe40d71c3e2381295e | Card must match the branch you measured |

### Stored data model
None.
