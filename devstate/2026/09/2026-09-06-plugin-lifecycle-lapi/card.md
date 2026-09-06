Developer review: in progress — 2026-09-06T05:25:11Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Motivation
On master, two stream middlewares that share a CrowdSec bouncer key but differ on any reclaim-identity field (metrics interval, update interval, Redis, timeout, failure action) start two `GET /v1/decisions/stream` pollers against one LAPI session. The pollers split the cursor; each cache uses a different `IdentityHex` prefix; bans apply on one router, the other, or neither. Matching e2e metrics labels only hides the split. If this does not land, operators keep a silent fail-open stream cache whenever two routers disagree on those knobs.

## Merge readiness
Not ready for review. Product delta versus `master` is journal only. Explore is next (attended stop).

Priority: P1 — stream remediations silently miss on a live LAPI session
Reviewed head: 182b45f
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | CI still running; no product apply yet |
| CI proof | 3/6 | in progress (Main Process, e2e mock, e2e pester) |
| Local tests proof | N/A | before implement; remote CI covers proof |
| Review resolution | 6/6 | OPEN PR #23, no review comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-plugin-lifecycle-lapi pushed | `git` origin |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/23 | pr-host Create |
| CI | build 34013928796 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34013928796 | pr-host check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | inventory empty |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec grounded on `2026-09-06-plugin-lifecycle-lapi` from `origin/master`, stub PR #23 opened in prepare, CI started on the empty+journal commits. Next phase is explore (stop after that card).

## Decision needed
None.

## Before merge
- [ ] Make stream session unique in-process (one poller per LAPI URL+key+scopes; conflict fails or shares) so two stream middlewares cannot steal one CrowdSec cursor
- [x] Stub PR #23 open from `2026-09-06-plugin-lifecycle-lapi`

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
| Reviewed head | 182b45f9038c3c5cce2e397b4c194a9f5cfd3bc3 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: not chosen yet; dest still hashes intervals into identity so two stream configs on one key become two pollers.

Do we have a high-confidence way to reproduce? Yes, two `Key(cfg)` with the same LAPI key and different `MetricsUpdateIntervalSeconds` hash differently (`pkg/crowdsecconnection/identity.go`); e2e already papered `/trusted` to match `/stream` metrics=1.

Is this the best way to solve the issue? Not yet — explore will pin fail-`New` versus share-session.

### Evidence
What I checked:
- Identity fields and missing `decisionScopeHeaders` (`pkg/crowdsecconnection/identity.go`, HEAD 182b45f)
- `startStream` / `streamQuery` / Redis prefix (`connection.go`, `connection_stream.go`, `connection_decisions.go`)
- Spec first-wins scenario (`openspec/specs/core_plugin_middleware_instance-reclaim/spec.md`)
- Compose workaround (`tests/e2e/real/docker-compose.test.yml` lines 274–276)
- LAPI cursor research (`knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`)
- OPEN PR #18 puts scopes on identity only
- CI check runs in progress (run 34013928796)

### Rank-up moves
None.
