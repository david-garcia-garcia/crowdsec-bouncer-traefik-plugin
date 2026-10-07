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
Reviewed head: 239609a4
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
| OpenSpec | appsec-http-version | `openspec/changes/appsec-http-version/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | comments.md absent |

## Specs
Delta:
- [core_plugin_appsec_client](openspec/changes/appsec-http-version/specs/core_plugin_appsec_client/spec.md) — fold

## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-10-07-appsec-http-version on branch 2026-10-07-appsec-http-version targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/189; CI not seen. OpenSpec change `appsec-http-version` folds `X-Crowdsec-Appsec-Http-Version` into `core_plugin_appsec_client`. Upstream report: https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/400. The PR summary was not updated because GitHub forms are broken.

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
| Reviewed head | 239609a4d97f1c0d66d3b87295f485d8c01fb59e | Card must match the branch you measured |

### Stored data model
None.
