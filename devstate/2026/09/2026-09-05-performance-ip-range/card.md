Developer review: in progress — 2026-09-05T15:33:54.693Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None. Ticket bus only; Range lookup on `origin/master` still walks the `range-index` blob on every stream/alone request.

**End users.** None.

## Motivation
On `origin/master`, stream and alone Range matching MGETs the whole `range-index` blob and tests every CIDR on each request. Allowed traffic (the common miss path) pays O(n) per lookup. Without this change, Range lists in the hundreds to thousands stay in the microsecond-to-sub-millisecond band on every request.

## Merge readiness
Prepare complete, stub PR open, product delta not started. 7 workflow items remain after this card.

Priority: P2 — real operator pain on the allowed-request path, with a workaround of keeping Range lists small
Reviewed head: 4e18707
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed; CI not measured; no product apply yet |
| CI proof | 1/6 | pushed and still not seen (`gh` not on PATH; GitHub MCP has no checks adapter) |
| Local tests proof | N/A | before implement (`localTests: none`) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-performance-ip-range pushed | `git push` origin |
| OpenSpec | none | `openspec/` unchanged vs master |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/14 | GitHub MCP Create |
| CI | not seen | Hosts CI adapter unavailable in this environment |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no `comments.md`; Comment-List empty |
| Security | None. | no `codereview.md` yet |
| Performance | None. | no `codereview.md` yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local spec grounded as `2026-09-05-performance-ip-range` on dest `master` (the branch that already has `pkg/iplookup` and `pkg/decisionscope`; `origin/main` does not). Stub PR #14 is the durable card host. Next is explore, then a spec delta so stream/alone Range lookup can use an in-process tree while Redis stays the shared document.

## Decision needed
None.

## Before merge
- [ ] Explore, propose, implement the in-process Range tree [P2]
- [ ] Spec deltas for `core_plugin_ip_radix-lookup` and `core_plugin_decisions_scopes`
- [ ] CI succeeded on PR #14
- [x] Stub PR opened
- [x] Requirement qualified

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
| Specs in this PR | none | Same list as ## Specs; do not paste diff --stat |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 4e18707f9f75cfcccfc782b85647de41c0fb0965 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus `origin/master`; the ticket’s two boolean `iplookup.Helper`s on `CrowdsecConnection` is the intended apply.

Do we have a high-confidence way to reproduce? Yes, existing `pkg/decisionscope` tests plus the request-path walk in `LookupCachedRemediation`.

Is this the best way to solve the issue? Not implemented yet. The ticket’s design is the candidate versus dest’s linear blob walk.

### Evidence
What I checked:
- Dest `origin/master` at 9de7722d625242bbdf8beb7e1cf642c947eca358 has `pkg/iplookup`, `pkg/decisionscope`; `origin/main` does not (`git ls-tree`)
- `LookupCachedRemediation` MGETs `RangeIndexKey` and `MatchRangeFromIndex` walks lines (`pkg/decisionscope/lookup.go`, `range.go`)
- `handleStreamCache` lease hit returns without reading `range-index` (`pkg/crowdsecconnection/connection.go`)
- Stub PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/14 (GitHub MCP)

### Rank-up moves
None.
