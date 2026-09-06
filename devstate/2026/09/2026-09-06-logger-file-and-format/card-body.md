Developer review: ready for review — 2026-09-06T15:15:00Z

## What this changes
**Operators.** File logging with `logFormat: JSON` (any casing) now emits structured JSON; reloads no longer accumulate extra file descriptors for the same `LogFilePath`.

**Admin users.** None.

**Developers.** `pkg/logger` reuses one process-lifetime `*os.File` per cleaned log path and selects JSON via case-insensitive match; new spec `std_go_logger_slog-output` with unit tests on `NewWithFormat`.

**End users.** None.

## Motivation
On `master`, `NewWithFormat` opens log files without closing them, so Traefik middleware reloads leak file descriptors when `LogFilePath` is set. Log format `"JSON"` silently falls back to text because only lowercase `"json"` selects the JSON handler, while `LogLevel` is already normalized in `plugin.go`. Without a fix, operators see wrong log shape in aggregators and growing FD use under reload.

## Merge readiness
All workflow phases complete. CI green on `f056a05`.

Priority: P2 — real operator pain (wrong log format, FD accumulation on reload) with workarounds (lowercase `json`, avoid file logging).
Reviewed head: f056a05
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready for review |
| CI proof | 6/6 | Main Process + e2e succeeded |
| Local tests proof | 6/6 | `go test ./pkg/logger/...` passed |
| Review resolution | 6/6 | No open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-logger-file-and-format pushed | git push f056a05 |
| OpenSpec | archived logger-file-and-format | openspec/changes/archive/2026-09-06-logger-file-and-format/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/29 | GitHub #29 |
| CI | succeeded | [Main Process](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041367195/job/101508617465), [e2e binary](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041367223/job/101508627043), [e2e docker](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34041367223/job/101508626999) |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | comments: none |

## Specs
- [std_go_logger_slog-output](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/openspec/changes/archive/2026-09-06-logger-file-and-format/proposal.md)

## Follow-up issues
None.

## How this fits together
Bug-hunt finding → explore chose process-lifetime shared file per path → `pkg/logger` fix + spec archive → PR #29 → CI green.

## Decision needed
None.

## Before merge
- [x] [P2] Explore close-on-reload vs shared process-lifetime file handle
- [x] [P2] Implement logger FD lifecycle and case-insensitive format in `pkg/logger`
- [x] [P2] Propose OpenSpec change and land tests
- [x] Prepare: requirement, worktree, stub PR
- [x] CI green on f056a05

## Findings
None.

## Axis review
- [Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/devstate/2026/09/2026-09-06-logger-file-and-format/codereview_standards.md): 1/1 completed
- [Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/devstate/2026/09/2026-09-06-logger-file-and-format/codereview_spec.md): 2/2 completed
- [Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/devstate/2026/09/2026-09-06-logger-file-and-format/codereview_security.md): 0 open
- [Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/devstate/2026/09/2026-09-06-logger-file-and-format/codereview_performance.md): 0 open
- [Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-logger-file-and-format/devstate/2026/09/2026-09-06-logger-file-and-format/codereview_dead.md): 1/1 completed

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | std_go_logger_slog-output (new) | Behavior contract for logger output |
| Open reviewer comments walked | 0 | No PR comments |
| Reviewed head | f056a05 | Latest push |

### Stored data model
None.

### Technical review
Best possible solution: yes — shared file per path avoids plugin Close wiring; EqualFold matches LogLevel normalization pattern.

Do we have a high-confidence way to reproduce? Yes — unit tests cover JSON casing and shared file map size.

Is this the best way to solve the issue? Yes for scoped pkg/logger bound; ValidateParams separate open remains out of scope.

### Evidence
What I checked:
- `pkg/logger/logger.go`, `pkg/logger/logger_test.go`
- `go test ./pkg/logger/...`
- CI Main Process + e2e on f056a05

### Rank-up moves
None.
