## Motivation
Not yet.

## Implementation
`Query` sets `X-Crowdsec-Appsec-Http-Version` in `newAppsecForwardRequest` from inbound `ProtoMajor` / `ProtoMinor` as two ASCII digits (`11`, `20`, `30`). The header is omitted when `ProtoMajor` is 0 so AppSec keeps the listener connection proto. Other `X-Crowdsec-Appsec-*` headers are unchanged.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
CI succeeded. Code review not started. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 97f9f3b7
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Implement landed; Motivation still for code review |
| CI proof | 6/6 | all 7 check runs success |
| Local tests proof | 6/6 | `go test ./pkg/appsec/` passed |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-07-appsec-http-version pushed | `git` |
| OpenSpec | appsec-http-version | `openspec/changes/appsec-http-version/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189 | pr-host |
| CI | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708507/job/113023082010 |
| Main Process | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708507/job/113023082010 |
| Race detector | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708507/job/113023081832 |
| e2e (go + dragonfly) | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708502/job/113023324791 |
| e2e (binary + mock LAPI) | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708502/job/113023324987 |
| e2e (docker + pester / appsec) | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708502/job/113023324540 |
| e2e (docker + pester / lapi) | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708502/job/113023324921 |
| e2e (docker + pester / lifecycle) | success | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/37688708502/job/113023324909 |
| Local tests | passed | `go test ./pkg/appsec/`; `golangci-lint run ./pkg/appsec/...` |
| PR comments | no comments | comments.md absent |

## Specs
Delta:
- [core_plugin_appsec_client](openspec/changes/appsec-http-version/specs/core_plugin_appsec_client/spec.md) — fold

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-07-appsec-http-version on branch 2026-10-07-appsec-http-version targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189; CI success on head 97f9f3b7. OpenSpec change `appsec-http-version` folds `X-Crowdsec-Appsec-Http-Version` into `core_plugin_appsec_client`. Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400. The PR summary was not updated because GitHub forms are broken.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Should Query omit the header when `ProtoMajor` is 0 (upstream PR 400 guard)? | additive incidental — optional skip on `ProtoMajor` 0; requirement does not name the upstream `if httpReq.ProtoMajor > 0` guard | assumed — omit when `ProtoMajor` is 0 so AppSec keeps connection proto instead of applying `"00"`. Real Traefik requests have `ProtoMajor` >= 1. | propose |
| How is HTTP/3 (`ProtoMajor` 3) encoded? | additive incidental — same two-digit encoding for `ProtoMajor` 3; Desired names `"10"` / `"11"` / `"20"` only | assumed — `fmt.Sprintf("%d%d", ProtoMajor, ProtoMinor)` so HTTP/3 is `"30"`. `applyHTTPVersion` accepts any two digits (`r.Proto` becomes `HTTP/3.0`). This plugin already inspects `ProtoMajor` >= 2 including 3 in `isBodyUnreadable`. | propose |

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | fold core_plugin_appsec_client | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 97f9f3b77a02ad80a049bec5ab54cb52c4d3caa8 | Card must match the branch you measured |
| Local tests | Test_appsecQuery_forwardsHTTPVersion | HTTP/1.1 → 11, HTTP/2 → 20, HTTP/3 → 30, ProtoMajor 0 → absent |

### Stored data model
None.
