Developer review: in progress — 2026-09-06T14:58:12Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None yet — prepare grounded two logger bugs (FD leak on file open, case-sensitive JSON format) in `pkg/logger`; implement not started.

**End users.** None.

## Motivation
On `master`, `NewWithFormat` opens log files without closing them, so Traefik middleware reloads leak file descriptors when `LogFilePath` is set. Log format `"JSON"` silently falls back to text because only lowercase `"json"` selects the JSON handler, while `LogLevel` is already normalized in `plugin.go`. Without a fix, operators see wrong log shape in aggregators and growing FD use under reload.

## Merge readiness
Prepare complete; explore is next. 7 workflow items remain.

Priority: P2 — real operator pain (wrong log format, FD accumulation on reload) with workarounds (lowercase `json`, avoid file logging).
Reviewed head: 2bc89a6
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Stub PR only; no product change or CI yet |
| CI proof | 1/6 | Pushed; CI not seen |
| Local tests proof | N/A | Before implement |
| Review resolution | N/A | No PR comments inventoried |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-logger-file-and-format pushed | git push |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/29 | GitHub MCP Create |
| CI | not seen | pr-host CI |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md absent |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local bug-hunt finding → branch `2026-09-06-logger-file-and-format` → stub PR #29 → explore next for close-vs-share and plugin cleanup hook.

## Decision needed
None.

## Before merge
- [ ] [P2] Explore close-on-reload vs shared process-lifetime file handle
- [ ] [P2] Implement logger FD lifecycle and case-insensitive format in `pkg/logger`
- [ ] [P2] Propose OpenSpec change and land tests
- [x] Prepare: requirement, worktree, stub PR

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | No product diff yet |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | No comments on stub PR |
| Reviewed head | 2bc89a6 | Matches pushed branch |

### Stored data model
None.

### Technical review
Best possible solution: not evaluated — no apply yet.

Do we have a high-confidence way to reproduce? Yes — unit tests can open temp log files and call `NewWithFormat` with `"JSON"` vs `"json"`.

Is this the best way to solve the issue? Not yet decided — explore must choose explicit `Close` vs shared writer.

### Evidence
What I checked:
- `pkg/logger/logger.go`, `plugin.go`, `pkg/logger/logger_test.go` (8186c16 / master)
- Local dump `devstate/bug-hunt/2026-09-06/logger/*.md`

### Rank-up moves
None.
