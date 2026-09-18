Developer review: in progress — 2026-09-18T18:10:59Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** `ServeHTTP` and `cache.Client` Get/GetMany/Set/Delete Debug now use slog attributes, so INFO does not `Sprintf` those strings. Hunt tests assert DEBUG stems plus fields.

**End users.** None.

## Motivation
Stream mode with the in-memory cache looks up a decision on every request, then allows when the cache says none. On `master`, that allow still builds debug strings first: `ServeHTTP` calls `fmt.Sprintf` for `ip` and `isTrusted` before the cache lookup, and `cache.Client` Get/GetMany (and Set/Delete) do the same. `slog.Debug` receives an already-built string, so INFO still pays `Sprintf`.

Ticket measure (compiled Go, logs to NUL): INFO allow 524 ns; DEBUG allow 2015 ns. High-traffic proxies must not run `logLevel` DEBUG, but the INFO path still allocates those strings.

If we do not merge, every stream allow keeps that formatting cost. The ticket does not ask to change log levels or logger file/format.

```mermaid
sequenceDiagram
  participant Req as ServeHTTP
  participant Log as slog.Debug
  participant Cache as cache.GetMany
  Req->>Req: Sprintf ip and isTrusted
  Req->>Log: already-built string
  Note over Log: INFO still paid Sprintf
  Req->>Cache: LookupCachedRemediation
  Cache->>Cache: Sprintf keys
  Cache->>Log: already-built string
  Req->>Req: allow
```

## Merge readiness
Six-axis review is clean; CI on this head is still in progress. 1 item remains.

Priority: P2 — INFO allow still formats debug strings on every stream request
Reviewed head: 890416b
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Apply and axis review landed; CI on this head is in progress |
| CI proof | 3/6 | in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35378467186 |
| Local tests proof | N/A | Remote PR; CI proof covers remote |
| Review resolution | 6/6 | OPEN PR #108; no reviewer comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-18-lazy-debug-log pushed | `git` / pr-host |
| OpenSpec | lazy-debug-hot-path | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/108 | pr-host List |
| CI | e2e (docker + pester) in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35378467223/job/105708757123 ; e2e (binary + mock LAPI) success https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35378467223/job/105708754958 ; Race detector in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35378467186/job/105708710664 ; Main Process in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35378467186/job/105708710423 | pr-host CI |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | no `comments.md` |

## Specs
- [std_go_logger_debug-attrs](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/openspec/changes/lazy-debug-hot-path/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Local ticket `2026-09-18-lazy-debug-log` runs on branch `2026-09-18-lazy-debug-log` as PR #108. Six-axis review is clean; devdocs impact is next.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| slog attributes or `Enabled` before `Sprintf` on the hot path? | assumed — slog attributes. Same fields, recognizable message stems, no `ctx`, no format string on INFO. | explore |
| Must Set/Delete change in the same apply (ticket names them; desired says Get/GetMany at minimum)? | assumed — yes. They share the Debug `Sprintf` pattern on `cache.Client`. Leave `cache.New`. | explore |
| Which other ServeHTTP Debug lines change for Symmetry? | assumed — every Debug `Sprintf`/`+` in `ServeHTTP`. Leave `handleRemediationServeHTTP` and AppSec Debug. Leave Error/Warn. | explore |
| Re-measure ticket ns (INFO 524 / DEBUG 2015) before proposing? | assumed — no. Call sites match. Implement adds tests that INFO does not emit Debug; do not require a committed benchmark. | explore |
| Write a stdlib slog research folder? | assumed — no. Evaluation-before-Enabled is stdlib; ticket already states it. | explore |

## Before merge
- [x] [P2] On `ServeHTTP` and cache Get/GetMany (at minimum), do not evaluate `fmt.Sprintf` unless Debug is enabled; keep the fields.
- [ ] CI on this head succeeded.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-18-lazy-debug-log/devstate/2026/09/2026-09-18-lazy-debug-log/codereview_coverage.md) — 0 total, 0 pending, 0 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 890416b8843fa9862ac3c2ebd0d3e92702847e1c | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: DestBranch `Sprintf`s before `Debug`. This head passes existing values as slog attributes on the request path.

Do we have a high-confidence way to reproduce? Yes — DestBranch call sites `Sprintf` then `Debug`. Local tests passed. Six-axis review: none.

Is this the best way to solve the issue? Yes versus DestBranch: slog attributes so INFO does not format those strings.

### Evidence
What I checked:
- Product delta `origin/master...HEAD` is OpenSpec `lazy-debug-hot-path` plus `pkg/bouncer` / `pkg/cache` Debug attributes and hunt tests
- Axis files all `none.`
- Local tests passed (`go test ./pkg/cache/ ./pkg/bouncer/ ./pkg/logger/ -count=1`)
- OPEN PR #108; comment inventory empty (pr-host)
- CI on this head: one success, three in progress (pr-host check runs)

### Rank-up moves
None.
