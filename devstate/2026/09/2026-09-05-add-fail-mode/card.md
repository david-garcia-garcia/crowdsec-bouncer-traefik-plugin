Developer review: in progress — 2026-09-05T12:07:21.136Z

IssueKey: 2026-09-05-add-fail-mode
JobName: 2026-09-05-add-fail-mode

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Ticket bus and requirement for `AppsecFailMode` / `LapiFailMode` on `devstate/2026/09/2026-09-05-add-fail-mode/`. No plugin keys on `master` yet.

**End users.** None.

## Motivation
On `master`, LAPI and AppSec unavailability is split across `updateMaxFailure` (stream/alone ban-all), live lookups that return banned on any LAPI error, and three AppSec booleans. Operators have no single fail-open/fail-closed policy per backend. Without this change that split stays the public contract.

## Merge readiness
Prepare complete; this run stops after explore. 1 item remains.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: b69a7bc
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR only; CI not seen; explore not started |
| CI proof | 1/6 | Pushed; checks not seen |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | N/A | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-fail-mode pushed | `git` origin/2026-09-05-add-fail-mode @ b69a7bc |
| OpenSpec | none | `openspec/` unchanged vs master |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/10 | pr-host Create |
| CI | not seen | pr-host CI not queried after push |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pr-host Comment-List empty |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-05-add-fail-mode` on dest `master`, stub PR 10. Caller asked to stop after explore so fail-mode does not silently fight `UpdateMaxFailure` and the AppSec block booleans.

## Decision needed
None.

## Before merge
- [ ] Explore `LapiFailMode` vs `UpdateMaxFailure` and `AppsecFailMode` vs the existing AppSec block booleans, then stop (caller).

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b69a7bc19b2351b0817026300609f19467d349cb | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet — prepare only mapped current knobs; no design.

Do we have a high-confidence way to reproduce? Yes, by reading `handleStreamTicker`, `queryLiveDecisions`, and `AppsecQuery` on `master`.

Is this the best way to solve the issue? Not yet — explore must decide whether new enums replace or wrap the existing knobs.

### Evidence
What I checked:
- `UpdateMaxFailure` default 0 and stream unhealthy ban-all (`pkg/crowdsecconnection/connection.go`, `pkg/bouncer/bouncer.go`, dest HEAD 4c07224)
- Live LAPI error returns `BannedValue` (`pkg/crowdsecconnection/connection_decisions.go`)
- AppSec `FailureBlock` / `UnreachableBlock` / `UnreadableBodyBlock` (`pkg/crowdsecconnection/connection.go` `AppsecQuery`)
- Stub PR 10 created from empty start commit plus destate requirement

### Rank-up moves
None.
