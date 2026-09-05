Developer review: in progress — 2026-09-05T15:41:04.873Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `in-process-range-membership` is apply-ready: stream/alone Range request matching will use in-process membership rebuilt from `range-index`. Deltas fold into `core_plugin_decisions_scopes` and `core_plugin_ip_radix-lookup`. Product code is not applied yet. This branch also adds `knowledge/research/ext_crowdsec_lapi_stream-cursor/`.

**End users.** None.

## Motivation
On `origin/master`, stream and alone Range matching MGETs the whole `range-index` blob and tests every CIDR on each request. Allowed traffic (the common miss path) pays O(n) per lookup. Without this change, Range lists in the hundreds to thousands stay in the microsecond-to-sub-millisecond band on every request.

## Merge readiness
Proposal is apply-ready. Implementation, review, archive, and green CI remain.

Priority: P2 — real operator pain on the allowed-request path, with a workaround of keeping Range lists small
Reviewed head: d9baf45
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Specs proposed; CI not measured; apply not started |
| CI proof | 1/6 | pushed and still not seen |
| Local tests proof | N/A | before implement (`localTests: none`) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-performance-ip-range pushed | `git push` origin |
| OpenSpec | in-process-range-membership | `openspec/changes/in-process-range-membership/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/14 | GitHub MCP |
| CI | not seen | Hosts CI adapter unavailable in this environment |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |
| Security | None. | no `codereview.md` yet |
| Performance | None. | no `codereview.md` yet |

## Specs
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-performance-ip-range/openspec/changes/in-process-range-membership/proposal.md) — modified
- [core_plugin_ip_radix-lookup](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-performance-ip-range/openspec/changes/in-process-range-membership/proposal.md) — modified

## Follow-up issues
None.

## How this fits together
FindSpecHost folded both deltas into existing leaves. Next is implement: `RangeMembership` on `CrowdsecConnection`, request path without MGET of `range-index`, ticker hydrate for Redis followers.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Generation key (`range-index-gen`) or blob-string compare on follower ticks? | assumed — compare the raw `range-index` string to the last hydrated blob; skip a `range-index-gen` key. | explore |
| Where does `LookupCachedRemediation` get the trees? | assumed — add a `*RangeMembership` argument owned by `pkg/decisionscope`. | explore |
| When is the first hydrate relative to serving? | assumed — `startStream` GETs `range-index` and builds membership before returning (no extra LAPI call). | explore |
| How do request-path reads see a rebuild? | assumed — build a new Helper pair from the blob, then store it with `atomic.Value`. | explore |
| What if Redis is unreachable during a follower hydrate? | assumed — keep the last membership; do not replace it with empty. | explore |

## Before merge
- [ ] Implement in-process Range membership [P2]
- [ ] CI succeeded on PR #14
- [x] OpenSpec change apply-ready
- [x] Explore written

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
| Specs in this PR | 0 added / 2 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | d9baf45eaa10681816c17dfbebdbd78c9b68c23a | Card must match the branch you measured |

### Stored data model
None. Redis `range-index` format unchanged.

### Technical review
Best possible solution: Two boolean Helpers on the reclaim value, rebuild from the blob — versus dest’s per-request blob walk.

Do we have a high-confidence way to reproduce? Yes. Specs encode the replica-hydrate and ban-wins-over-longer-captcha cases.

Is this the best way to solve the issue? Yes versus dest. One LPM tree with a stored remediation would hide a containing ban.

### Evidence
What I checked:
- `openspec validate in-process-range-membership --strict --type change` passed
- Fold: `core_plugin_decisions_scopes`, `core_plugin_ip_radix-lookup` (`openspec/specs/map.md`)

### Rank-up moves
None.
