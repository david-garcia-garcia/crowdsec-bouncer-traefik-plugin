## Motivation
CrowdSec bot-detection challenges call back under `/crowdsec-internal/challenge/`. Those URLs must stay inside the middleware so AppSec can serve them; they must not reach origin.

On this tree, `handleNextServeHTTP` calls `next` whenever AppSec returns nil (HTTP 200, or 500/unreachable with the matching Block flag false). AppSec allows `/crowdsec-internal/challenge/custom.js` when no custom script is configured, so a host-wide middleware still leaks that prefix to the backend.

Leaving it leaks CrowdSec's internal challenge URLs to origin, which the protocol forbids.

Priority: P1 — leaking `/crowdsec-internal/challenge/` to origin is a wrong public contract today

## Implementation
After a nil `appsecQuery` while AppSec is enabled, `handleNextServeHTTP` responds 404 for any `req.URL.Path` with prefix `/crowdsec-internal/challenge/` and does not call `next`. AppSec errors still ban. Paths outside the prefix still call `next` on allow. Trusted IPs still skip in `ServeHTTP` before this function. README documents the 404. Main CI maps GOPATH to the go.mod module path so Yaegi can resolve this fork.

## What this changes
**Operators.** The plugin 404s `/crowdsec-internal/challenge/*` when AppSec is enabled and does not serve the path; covering the host with middleware is not enough without that 404. Clients in `bouncerClientTrustedIps` still skip the plugin.
**Admin users.** None.
**Developers.** `handleNextServeHTTP` 404s `/crowdsec-internal/challenge/` after a nil AppSec query and does not call `next`. This fork's Main workflow maps GOPATH so Yaegi finds `github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin`.
**End users.** Requests under `/crowdsec-internal/challenge/` that AppSec does not serve receive HTTP 404 instead of origin content.

## Merge readiness
In progress. 0 items remain.

Priority: P1 — leaking `/crowdsec-internal/challenge/` to origin is a wrong public contract today
Reviewed head: 38114bc1
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
| Branch | 2026-10-13-challenge-path-terminate pushed | `git` |
| OpenSpec | terminate-internal-challenge-paths | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/192 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: Update the spec and the README sentence that tells operators the prefix is safe whenever the middleware covers the host. → dest `main` has no OpenSpec catalog; document the 404 in README only. — `README.md` — honouring the wording would bootstrap `openspec/` as a new catalog on dest, which has no spec leaves or callers.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-13-challenge-path-terminate on branch 2026-10-13-challenge-path-terminate targeting main; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/192; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-13-challenge-path-terminate/devstate/2026/10/2026-10-13-challenge-path-terminate/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 38114bc1b5e95131495e964cbaabf1146f6984ed | Card must match the branch you measured |

### Stored data model
None.
