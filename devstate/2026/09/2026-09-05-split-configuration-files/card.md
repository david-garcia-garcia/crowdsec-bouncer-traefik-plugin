Developer review: in progress — 2026-09-05T16:26:05Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None. Product code versus `master` is unchanged; this branch only opened the review PR and recorded the prepare bus.

**End users.** None.

## Motivation
On `master`, `pkg/configuration/configuration.go` holds the Traefik Config DTO, enums, file secrets, template compile, validation, and runtime LAPI/AppSec TLS construction in one 600-line file. Leaving it mixed keeps the TLS builder in the config bag instead of next to the HTTP clients that use it, so later edits keep touching five jobs at once.

## Merge readiness
Not ready for review. 1 item remains.

Priority: P3 — Spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 60413b1
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Stub PR is open; CI is still running; no product apply yet |
| CI proof | 3/6 | Main Process in progress |
| Local tests proof | N/A | Before implement; remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-split-configuration-files pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/17 | GitHub MCP Create |
| CI | build 33977812781 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33977812781 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read |
| Security | None. | not reviewed yet |
| Performance | None. | not reviewed yet |
| Dead | None. | not reviewed yet |

## Specs
None.

## Follow-up issues
None.

## How this fits together
Local ticket 2026-09-05-split-configuration-files is grounded on this branch. Stub PR 17 is the durable card host. Qualify is qualified. Apply has not started.

## Decision needed
None.

## Before merge
- [ ] Apply the configuration file split and TLS move versus `master`
- [ ] Wait for CI on PR 17 after the apply

## Findings
None.

## Agent review details

### Security
None.

### Performance
None.

### Dead
None.

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | none | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 60413b1cd2475f0be19ccf3b72bc32e1892d40c2 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus `master`; prepare only recorded the split of `configuration.go` and the TLS move into `pkg/crowdsecconnection`.

Do we have a high-confidence way to reproduce? Yes, `pkg/configuration/configuration.go` and `GetTLSConfigCrowdsec` call sites are on `master` at `2d4acf3`.

Is this the best way to solve the issue? Not applied yet.

### Evidence
What I checked:
- `pkg/configuration/configuration.go` holds DTO, enums, GetVariable, GetTemplate, ValidateParams, and GetTLSConfigCrowdsec (worktree, 2d4acf3)
- `pkg/crowdsecconnection/connection.go` New attaches TLS to http.Client (worktree, 2d4acf3)
- Stub PR 17 created; comments empty (GitHub MCP)
- CI Main Process in progress (check run 101337504284, 2026-09-05T16:25:24Z)

### Rank-up moves
None.
