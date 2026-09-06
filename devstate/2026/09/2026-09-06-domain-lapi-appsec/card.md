Developer review: in progress — 2026-09-06T12:19:10Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Ticket bus only under `devstate/2026/09/2026-09-06-domain-lapi-appsec/` on `2026-09-06-domain-lapi-appsec`. No LAPI/AppSec package split on `master` yet.

**End users.** None.

## Motivation
On `master`, `pkg/crowdsecconnection` is one reclaim type for CrowdSec LAPI decisions and AppSec WAF. Developers cannot change one job without reading the other, and spec `core_plugin_connection_source-files` still forbids a new import path. Without this work, later LAPI and AppSec changes keep landing in the same type.

## Merge readiness
Prepare grounded the ticket; the product split has not started. Explore and later phases remain.

Priority: P3 — internal package clarity, no current operator or user harm
Reviewed head: 02f6862
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI is still running; no product apply yet |
| CI proof | 3/6 | in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032727002 |
| Local tests proof | N/A | `localTests: none` (before implement) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-domain-lapi-appsec pushed | `git` origin/2026-09-06-domain-lapi-appsec |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/26 | pr-host Create |
| CI | build 34032727002 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032727002 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read get_comments |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local chat spec → branch `2026-09-06-domain-lapi-appsec` from `origin/master` in worktree `wt-modsec-2026-09-06-domain-lapi-appsec` → stub PR 26. This run stops after explore so the split strategy can be agreed.

## Decision needed
None.

## Before merge
- [ ] Agree LAPI vs AppSec package split in explore, then propose
- [x] Stub PR 26 opened
- [x] Requirement written (`qualified-with-gaps`)

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
| Reviewed head | 02f68621ce19b1c7b8c6107709c242c2cf792f3f | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applicable — product delta versus `master` is the ticket bus only.

Do we have a high-confidence way to reproduce? Yes, the coupling is in `pkg/crowdsecconnection/connection.go` on `master` (`CrowdsecConnection` holds LAPI and AppSec clients).

Is this the best way to solve the issue? Not yet — package names, reclaim, and `appsec` mode still need explore.

### Evidence
What I checked:
- `origin/master` HEAD `5d83649f6305b8e421287bab81713abd8274fd42` has `pkg/crowdsecconnection` (`git ls-tree`)
- Spec `openspec/specs/core_plugin_connection_source-files/spec.md` forbids a new import path
- Whoami `David <deivid.garcia.garcia@gmail.com>`
- PR 26 comments empty; checks in progress (GitHub MCP)

### Rank-up moves
None.
