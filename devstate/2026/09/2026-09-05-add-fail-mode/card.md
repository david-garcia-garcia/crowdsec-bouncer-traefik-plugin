Developer review: in progress — 2026-09-05T12:13:02.444Z

IssueKey: 2026-09-05-add-fail-mode
JobName: 2026-09-05-add-fail-mode

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** Explore journal plus research `ext_crowdsec_bouncers_failure-action/` and `ext_crowdsec_appsec_protocol/`. No `lapiFailMode` / `appsecFailMode` keys on `master` yet.

**End users.** None.

## Motivation
On `master`, LAPI and AppSec unavailability is split across `updateMaxFailure` (stream/alone), live lookups that ban on any LAPI error, and three AppSec booleans. CrowdSec's spec uses `lapi_failure_action` / `appsec_failure_action` (default passthrough). Without a named fail-mode, operators cannot set one policy per backend, and a naive new key would fight those knobs.

## Merge readiness
Explore complete; this run stops here. Owner decision required. 6 items remain on Decision needed.

Priority: P2 — real operator pain, with a workaround or limited blast radius
Reviewed head: f24a365
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore done; CI in progress; no product keys |
| CI proof | 3/6 | Checks in progress on run 33965408137 / 33965408138 |
| Local tests proof | N/A | Before implement (`localTests: none`) |
| Review resolution | N/A | No PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-add-fail-mode pushed | `git` @ f24a365 |
| OpenSpec | none | `openspec/` unchanged vs master |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/10 | pr-host |
| CI | build 33965408137 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965408137 ; build 33965408138 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33965408138 | pr-host get_check_runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pr-host Comment-List empty |
| Security | None. | destate/codereview.md absent |
| Performance | None. | destate/codereview.md absent |

## Specs
None.

## Follow-up issues
- [ ] [note] [large] Rename `crowdsecAppsecFailureBlock` / `crowdsecAppsecUnreachableBlock` → `appsecFailMode` — replacing published Traefik plugin keys is a contract break. Explore assumed replace.
- [ ] [note] [large] `updateMaxFailure` vs new `lapiFailMode` — they overlap stream unavailability. Explore assumed wrap.

## How this fits together
Local ticket on dest `master`, stub PR 10. Explore mapped the fights and stopped. Propose does not start until the Decision needed rows are accepted or changed.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Does `LapiFailMode` replace `UpdateMaxFailure`, or only name the action after the counter trips? | assumed — wrap, do not delete. Keep `UpdateMaxFailure` as the stream/alone unhealthy counter. `LapiFailMode` is the ServeHTTP action on cache miss when unhealthy, and the LiveLookup error action. `-1` still means never unhealthy. | explore |
| What happens in live mode, which has no counter and already returns `BannedValue` on any LAPI error? | assumed — live uses `LapiFailMode` per request (no new counter). `passthrough` → treat the error as allow; `ban` → current `BannedValue`; `captcha` only if a captcha provider is configured, else validate as ban. | explore |
| Does one `AppsecFailMode` replace `CrowdsecAppsecFailureBlock` + `CrowdsecAppsecUnreachableBlock`? | assumed — replace those two booleans with one enum aligned to CrowdSec `appsec_failure_action` (`passthrough` \| `ban` \| `captcha`). Same action for HTTP 500 and unreachable. Keep `CrowdsecAppsecUnreadableBodyBlock`. | explore |
| Which JSON key names and which enum strings? | assumed — public keys `lapiFailMode` and `appsecFailMode`. Values `passthrough` \| `ban` \| `captcha`. Defaults stay this plugin's fail-closed: `ban` (not spec passthrough). | explore |
| When stream is unhealthy, should `passthrough` skip AppSec too, or still call AppSec on the pass path? | assumed — `LapiFailMode=passthrough` uses the existing pass path, so AppSec still runs if enabled. | explore |
| Who owns the new keys on reclaim — CrowdsecConnection identity vs per-router Bouncer? | assumed — `LapiFailMode` on CrowdsecConnection identity (with `UpdateMaxFailure`). `AppsecFailMode` on Bouncer / `AppsecPolicy`, not in identity. | explore |

## Before merge
- [ ] [P2] Human accept or rewrite the Decision needed rows before propose.
- [ ] Do not start propose until that answer (caller stop at explore).

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
| Reviewed head | f24a365ede0b78b97ea6744acb708bf3dcbfca51 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet — wrap `UpdateMaxFailure` and replace the two AppSec bools is the assumed shape vs `master`; the human can pick otherwise.

Do we have a high-confidence way to reproduce? Yes — `go test ./pkg/crowdsecconnection/` passed; stream-unhealthy ServeHTTP has no unit test and was traced in source.

Is this the best way to solve the issue? Not yet — Decision needed.

### Evidence
What I checked:
- `handleStreamTicker` / `ServeHTTP` stream unhealthy (`pkg/crowdsecconnection/connection.go`, `pkg/bouncer/bouncer.go`, dest 4c07224)
- Live LAPI error → `BannedValue` (`pkg/crowdsecconnection/connection_decisions.go`)
- `AppsecQuery` 500 vs unreachable vs other non-200 (`pkg/crowdsecconnection/connection.go`)
- Official `lapi_failure_action` / `appsec_failure_action` (`knowledge/research/ext_crowdsec_bouncers_failure-action/`)
- `go test ./pkg/crowdsecconnection/` passed
- CI in progress (runs 33965408137, 33965408138)

### Rank-up moves
None.
