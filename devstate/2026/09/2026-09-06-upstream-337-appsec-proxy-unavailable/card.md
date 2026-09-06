Developer review: in progress — 2026-09-06T15:06:10Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
Upstream #337 reported that when AppSec is reached through an L7 proxy and CrowdSec is down, HTTP 502/503/504 from the proxy caused Traefik to ban (403) even with passthrough configured. On `master`, code paths treat those statuses as unreachable via `isReverseProxyError`, but no test proves passthrough on HTTP 502/503/504. Without this PR, a regression could reintroduce the upstream bug silently.

## Merge readiness
Not ready for review. Prepare complete; explore is next. Product delta versus `master` is journal only.

Priority: P3 — tests and regression proof; no current user harm on `master` if behavior already correct
Reviewed head: d34bb90
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR open; no product apply or CI success yet |
| CI proof | 1/6 | pushed; checks not seen |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #46, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-upstream-337-appsec-proxy-unavailable pushed | `git` origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/46 | pr-host |
| CI | not seen | pr-host |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec from upstream #337 assessment on `2026-09-06-upstream-337-appsec-proxy-unavailable` from `origin/master`, stub PR #46, requirement qualified for add-tests explore/implement.

## Decision needed
None.

## Before merge
- [ ] Add tests proving HTTP 502/503/504 AppSec responses honor `crowdsecAppsecFailureAction: passthrough`
- [x] Stub PR #46 open from `2026-09-06-upstream-337-appsec-proxy-unavailable`
- [x] Prepare wrote requirement and qualified ticket

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d34bb90 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — prepare only; assessment indicates fix likely present on `master`.

Do we have a high-confidence way to reproduce? No — tests to be added in implement.

Is this the best way to solve the issue? Yes — add-tests matches assessment `recommended-action` without changing behavior unless required for honest tests.

### Evidence
What I checked:
- Upstream #337 dump and assessment (`devstate/.../ticket/source.md`, commit d34bb90)
- Current AppSec unreachable handling (`pkg/appsec/query.go`, `pkg/appsec/client.go` on `master`)

### Rank-up moves
None.
