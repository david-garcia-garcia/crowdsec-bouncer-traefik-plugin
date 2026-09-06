Developer review: in progress — 2026-09-06T12:22:55Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Ticket bus plus `explore.md` on `2026-09-06-domain-lapi-appsec`. No `pkg/lapi` / `pkg/appsec` rename versus `master` yet.

**End users.** None.

## Motivation
On `master`, `pkg/crowdsecconnection` is one reclaim type for CrowdSec LAPI decisions and AppSec WAF. Developers cannot change one job without reading the other, and spec `core_plugin_connection_source-files` still forbids a new import path. Without this work, later LAPI and AppSec changes keep landing in the same type.

## Merge readiness
Explore recorded a split strategy; product apply waits on agreement. Several workflow items remain.

Priority: P3 — internal package clarity, no current operator or user harm
Reviewed head: c716d34
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product apply; assumed decisions need a human |
| CI proof | 3/6 | in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032850241 |
| Local tests proof | N/A | `localTests: none` (before implement) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-domain-lapi-appsec pushed | `git` origin/2026-09-06-domain-lapi-appsec |
| OpenSpec | none | `openspec list --json` empty |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/26 | pr-host List |
| CI | build 34032850241 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032850241 | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read get_comments |

## Specs
None.

## Follow-up issues
- [ ] [take] [small] Spec `core_plugin_connection_source-files` → lapi + appsec package-layout specs — that spec names `package crowdsecconnection` and forbids a new import path. Not taken: propose FindSpecHost.

## How this fits together
Local chat spec → worktree `wt-modsec-2026-09-06-domain-lapi-appsec` → stub PR 26. Explore is written; this run stops here so the split strategy can be agreed before propose.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| What is the AppSec package name? | assumed — `pkg/appsec` (CrowdSec product name). Not `waf`, not `crowdsecappsec`. | explore |
| What is the LAPI reclaim type name inside `package lapi`? | assumed — `lapi.Connection`. Drop exported `CrowdsecConnection`. | explore |
| Is AppSec reclaimed separately, or constructed inside LAPI `New` as a field? | assumed — separate reclaim; Bouncer holds `*lapi.Connection` and `*appsec.Client` (nil when AppSec off). | explore |
| Live/none `IdentityHex` currently hashes AppSec host/key/TLS. Dropping those fields changes the live Redis cache prefix on upgrade. | assumed — drop AppSec from LAPI identity. Accept a one-time live-mode cache miss/TTL refresh. | explore |
| Stream warn-and-wire first-wins currently includes AppSec knobs. After split, two routers on one LAPI stream can use different AppSec hosts. | assumed — drop AppSec from `streamSettings`. Verdict protocol unchanged. | explore |
| For `crowdsecMode: appsec`, does plugin still Open a LAPI connection? | assumed — no LAPI Open. Bouncer stores `crowdsecMode` from config. AppSec Open still runs. | explore |
| Keep `Prepare` copying empty `crowdsecAppsecKey` from `crowdsecLapiKey` (and empty AppSec scheme from LAPI scheme)? | assumed — keep. | explore |
| Reclaim table key prefix `crowdsecconnection:` / `crowdsecconnection:stream:`? | assumed — `lapi:` / `lapi:stream:` and `appsec:`. | explore |

## Before merge
- [ ] Agree explore decisions, then propose
- [x] Explore written (`devstate/.../explore.md`)
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
| Reviewed head | c716d34d7b1faef2843f22bdbb3a106dca03a69f | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applicable — product delta versus `master` is the ticket bus only.

Do we have a high-confidence way to reproduce? Yes, the coupling is in `pkg/crowdsecconnection/connection.go` (`CrowdsecConnection` holds LAPI and AppSec clients); live identity and stream settings both hash AppSec fields.

Is this the best way to solve the issue? Recommended path is two packages and two reclaim keys (see Decision needed). Waiting on agreement.

### Evidence
What I checked:
- `CrowdsecConnection` AppSec fields and `AppsecQuery` method (`pkg/crowdsecconnection/connection.go`, `connection_appsec.go`)
- Live identity and stream settings include AppSec (`identity.go`, `session.go`)
- Spec `openspec/specs/core_plugin_connection_source-files/spec.md` forbids a new import path
- `openspec list --json` has no active change
- CI run 34032850241 in progress (GitHub MCP)

### Rank-up moves
None.
