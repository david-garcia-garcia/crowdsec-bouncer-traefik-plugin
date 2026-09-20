Developer review: needs changes — 2026-09-20T04:11:51.297Z

## What this changes

**Operators.** Redis decision slots and the `range-index` blob now store kind plus optional newline origin (`KindOriginString`). Leftover U+001F payloads and the stream lease key are gone. `traefik-middleware-utilities` is pinned at v1.0.5. No new deploy keys.

**Admin users.** None.

**Developers.** CrowdSec decisions live on `pkg/decisionstore.Store` with memory and Redis engine funcs bound at `NewMemory`/`NewRedis`. `pkg/cache`, stream lease, and a second `liveStore` type are gone. `LookupRemediation` and `LiveLookup` return kind and origin fields. Intern overflow Warns and keeps origin id 0. A constructed Store always has callbacks (no nil-store Close). Published vendor is v1.0.5; do not re-patch `iplookup/helper.go`. Usage packet is `knowledge/devdocs/core_plugin_decisionstore.md`.

**End users.** None.

## Motivation

On `origin/master`, stream and alone still resolve Ip and header decisions through the TTL cache heap, and Redis I/O sits behind `cache.Client` including a stream lease. That path is correct for a generic cache and wrong for a decision store that already has a tick cadence and a Range blob.

A miss on master allocates through GetInt/Get/GetMany. Redis and memory leak into `lapi.Client`. The cost of not merging is continued stream-memory lookup cost at master scale and a lease/cache bag that this plugin no longer owns.

```mermaid
sequenceDiagram
  participant Bouncer
  participant Client as lapi.Client
  participant Cache as cache.Client
  Bouncer->>Client: LookupRemediation
  Client->>Cache: GetInt / Get / GetMany
  Note over Cache: DestBranch: TTL heap on memory; lease plus slots on Redis
```

## Merge readiness

Usage docs produced (35c34cd4). One RETHINK comment stays `[ ]` until pullrequest Reply. CI is in progress on 3c17d396. 2 items remain.

Priority: P2 — stream/alone memory lookup cost and Redis/cache coupling on master, with no operator config change required.

Reviewed head: 3c17d396

Owner decision: None.

## Review scores

| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Open RETHINK `[ ]` blocks review resolution |
| CI proof | 3/6 | In progress on 3c17d396 — [Race detector](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35488523351/job/106019196815), [Main Process](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35488523351/job/106019196690) queued |
| Local tests proof | N/A | Remote `prHost`; CI proof covers remote |
| Review resolution | 1/6 | `comments.md` RETHINK `chat-store-split` still `[ ]` |

## Verification

| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-19-optcow-stream-lookup pushed | `git` / PR #118 → master |
| OpenSpec | 2026-09-19-optcow-stream-lookup | `openspec/changes/2026-09-19-optcow-stream-lookup/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/118 | GitHub |
| CI | build 35488523351 in_progress [Race detector](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35488523351/job/106019196815); Main Process queued | GitHub check runs |
| Local tests | passed | handoff.yaml `localTests: passed` (`go test` on decisionstore/lapi/bouncer/decisionscope) |
| PR comments | 1 open | `comments.md` RETHINK `chat-store-split` |

## Specs

- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — added
- [core_cache_client_decision-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_cache_client_isolated-store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_cache_redis_utilities-client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_lapi_stream-lease](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_lapi_stream-apply](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_lapi_stream-single-flight](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_lapi_usage-metrics](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [core_plugin_middleware_captcha-routing](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [std_go_logger_debug-attrs](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified
- [build_ci_github_module-path](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/openspec/changes/2026-09-19-optcow-stream-lookup/proposal.md) — modified

## Follow-up issues

None.

## How this fits together

Ticket `2026-09-19-optcow-stream-lookup` is branch `2026-09-19-optcow-stream-lookup` on PR #118 to `master`. Devdocs impact produced; CI is in progress on 3c17d396.

## Decision needed

None.

## Before merge

- [x] [P2] Six-axis hard findings applied (f92c8573)
- [x] [P2] Human product fixes: no nil-store Close; utilities v1.0.5 (6842765a)
- [x] [P3] Usage docs: `core_plugin_decisionstore.md`; cache/lease packets removed (35c34cd4)
- [ ] Close RETHINK `chat-store-split` after pullrequest Reply
- [ ] Green CI on reviewed head

## Findings

- [chat-store-split](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/118) — RETHINK — store split landed as `pkg/decisionstore.Store` engines, not `Client` cache branching. Path: (general). Reply pending pullrequest.
- Six-axis hard/wrong items applied in f92c8573; skipped IPCacheKey rename (ticket pin) and three judgement items.

## Axis review

[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_standards.md) — 36 total, 0 pending, 33 completed, 3 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_performance.md) — 2 total, 0 pending, 2 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_dead.md) — 1 total, 0 pending, 1 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-19-optcow-stream-lookup/devstate/2026/09/2026-09-19-optcow-stream-lookup/codereview_coverage.md) — 6 total, 0 pending, 5 completed, 1 skipped

## Agent review details

### Review metrics

| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 13 modified | Same list as ## Specs |
| Open reviewer comments walked | 1 FIX / 0 ANSWER / 1 open | Unanswered RETHINK is merge risk |
| Reviewed head | 3c17d396cf5adcc1069f216843aeb5301e9156c6 | Card matches measured branch |

### Stored data model

- Changed: Redis slot value / remediation payload — string — sample `t` + U+001F + `crowdsec` → `t` + newline + `crowdsec`. Upgrade: rewritten on next write.
- Changed: Redis key `range-index` / value after `=` — string — sample `10.0.0.0/8=t` + U+001F + `crowdsec` → `10.0.0.0/8=t` + newline + `crowdsec`. Upgrade: rewritten on next write.
- Changed: Redis key `<SessionHex>:updated` stream lease — removed. Upgrade: leftover lease keys unused.

### Technical review

Best possible solution: one DecisionStore engine (memory COW or Redis SimpleRedis) instead of DestBranch `cache.Client` plus TTL heap for stream/alone slots.

Do we have a high-confidence way to reproduce? Yes, `go test ./pkg/decisionstore/ ./pkg/lapi/ ./pkg/bouncer/ ./pkg/decisionscope/` and the new tick/overflow/replica tests.

Is this the best way to solve the issue? Yes versus DestBranch: store owns Put/Lookup/Range; Client does not branch cache vs scratch map.

### Evidence

What I checked:
- Six-axis Status after apply (run-root `codereview_*.md`, 5936ac7a)
- Product apply `f92c8573` (leftover drop, live sweep, Pack delete, coverage tests)
- Human pins `6842765a` (no nil-store Close; utilities v1.0.5)
- GitHub check runs on 3c17d396 (in_progress)
- Usage packets produced (`knowledge/devdocs/core_plugin_decisionstore.md`, 35c34cd4)

### Rank-up moves

- Reply `chat-store-split` in pullrequest (landed store is engines, not `streamStore`/`cache.Client`).
