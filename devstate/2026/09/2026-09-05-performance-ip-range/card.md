Developer review: in progress — 2026-09-05T15:37:13.191Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** This branch adds `knowledge/research/ext_crowdsec_lapi_stream-cursor/` (LAPI stream cursor is per bouncer row, not per API-key string). Range lookup on the request path is still the linear `range-index` walk.

**End users.** None.

## Motivation
On `origin/master`, stream and alone Range matching MGETs the whole `range-index` blob and tests every CIDR on each request. Allowed traffic (the common miss path) pays O(n) per lookup. Without this change, Range lists in the hundreds to thousands stay in the microsecond-to-sub-millisecond band on every request.

## Merge readiness
Explore written; product apply not started. Spec deltas and implementation remain.

Priority: P2 — real operator pain on the allowed-request path, with a workaround of keeping Range lists small
Reviewed head: 0dd605c
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Pushed; CI not measured; Range tree not applied |
| CI proof | 1/6 | pushed and still not seen (`gh` not on PATH; GitHub MCP has no checks adapter) |
| Local tests proof | N/A | before implement (`localTests: none`); explore ran `go test ./pkg/decisionscope ./pkg/iplookup` (pass) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-performance-ip-range pushed | `git push` origin |
| OpenSpec | none | `openspec/changes/` empty |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/14 | GitHub MCP |
| CI | not seen | Hosts CI adapter unavailable in this environment |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |
| Security | None. | no `codereview.md` yet |
| Performance | None. | no `codereview.md` yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Explore chose two in-process `iplookup.Helper`s on `CrowdsecConnection`, blob still the shared document, follower hydrate on lease hit. Next is propose (spec deltas for radix-lookup and decision scopes).

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Generation key (`range-index-gen`) or blob-string compare on follower ticks? | assumed — compare the raw `range-index` string to the last hydrated blob; skip a `range-index-gen` key. Typical Range cardinality is small. Revisit only if blob GET becomes a problem. | explore |
| Where does `LookupCachedRemediation` get the trees? | assumed — add a `*RangeMembership` argument owned by `pkg/decisionscope`. Bouncer passes `conn`’s current membership. Do not look up Range inside `pkg/ip.Checker`. Do not add package globals. | explore |
| When is the first hydrate relative to serving? | assumed — `startStream` GETs `range-index` and builds membership before returning (no extra LAPI call). Redis followers match Range on the first request if the blob already exists. No-Redis: empty until this process’s first stream apply (same as empty blob today). `StreamStartupBlock` still controls whether the first LAPI poll is synchronous. | explore |
| How do request-path reads see a rebuild? | assumed — build a new Helper pair from the blob, then store it with `atomic.Pointer`. Do not mutate a Helper in place (no delete API). A reader sees the previous complete pair or the new complete pair. | explore |
| What if Redis is unreachable during a follower hydrate? | assumed — keep the last membership; do not replace it with empty. Same fail posture as today’s cache Get errors on the request path (`RedisUnreachableBlock`). | explore |

## Before merge
- [ ] Propose and implement the in-process Range membership [P2]
- [ ] Spec deltas for `core_plugin_ip_radix-lookup` and `core_plugin_decisions_scopes`
- [ ] CI succeeded on PR #14
- [x] Explore written
- [x] Stub PR opened

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 0dd605c925e8e15da3224f882bd28437cd517358 | Card must match the branch you measured |

### Stored data model
None. Redis `range-index` format unchanged. No generation key this change.

### Technical review
Best possible solution: Two boolean Helpers on the reclaim value, rebuild from the blob, hydrate followers on the ticker — versus dest’s per-request blob walk.

Do we have a high-confidence way to reproduce? Yes. `MatchRangeFromIndex` still walks every line; `go test ./pkg/decisionscope ./pkg/iplookup` passed.

Is this the best way to solve the issue? Yes versus dest. One LPM tree with a stored remediation would hide a containing ban behind a longer captcha prefix.

### Evidence
What I checked:
- `go test ./pkg/decisionscope ./pkg/iplookup` passed (explore)
- `LookupCachedRemediation` still MGETs `RangeIndexKey` (`pkg/decisionscope/lookup.go`)
- Reclaim: tree belongs on `CrowdsecConnection`, not `sync.Once` (`knowledge/devdocs/core_plugin_middleware.md`, `std_go_reclaim.md`)
- LAPI cursor is per bouncer row (`knowledge/research/ext_crowdsec_lapi_stream-cursor/notes.md`)

### Rank-up moves
None.
