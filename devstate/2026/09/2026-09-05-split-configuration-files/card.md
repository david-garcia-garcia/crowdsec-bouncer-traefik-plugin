Developer review: in progress — 2026-09-05T16:49:50Z

## What this changes
**Operators.** None. Traefik YAML keys and TLS outcomes stay as on `master`.

**Admin users.** None.

**Developers.** `pkg/configuration` is split into `config.go`, `secrets.go`, `template.go`, and `validate.go`. Runtime LAPI/AppSec TLS construction lives in `pkg/crowdsecconnection/tls.go` (unexported). Mock captcha e2e waits 45s for the stream poll, matching custom ban.

**End users.** None.

## Motivation
On `master`, `pkg/configuration/configuration.go` holds the Traefik Config DTO, enums, file secrets, template compile, validation, and runtime LAPI/AppSec TLS construction in one 600-line file. Leaving it mixed keeps the TLS builder in the config bag instead of next to the HTTP clients that use it, so later edits keep touching five jobs at once.

## Merge readiness
Not ready for review. 2 items remain.

Priority: P3 — Spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 2fe6288
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Apply landed; local tests passed; CI succeeded |
| CI proof | 6/6 | Main Process, mock e2e, and docker e2e succeeded |
| Local tests proof | N/A | Remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-split-configuration-files pushed | git |
| OpenSpec | split-configuration-files | openspec/changes/split-configuration-files/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/17 | GitHub MCP |
| CI | build 33978900213 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978900213 ; e2e 33978900205 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978900205 | GitHub check runs |
| Local tests | passed | go test ./pkg/configuration/ ./pkg/crowdsecconnection/ ./pkg/captcha/ ./pkg/bouncer/ |
| PR comments | no comments | pull_request_read |
| Security | None. | not reviewed yet |
| Performance | None. | not reviewed yet |
| Dead | None. | not reviewed yet |

## Specs
- [core_plugin_config_file-owners](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-split-configuration-files/openspec/changes/split-configuration-files/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Implement split the configuration package and moved TLS construction next to LAPI/AppSec HTTP clients. PR 17 CI is green. Archive and pullrequest remain.

## Decision needed
None.

## Before merge
- [ ] Archive the OpenSpec change into `openspec/specs/`
- [ ] Drop the WIP title on PR 17

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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 2fe6288dc50ca5a850874034c8b369a30a5ebce7 | Card must match the branch you measured |

### Stored data model
None. Config JSON tags unchanged versus `master`.

### Technical review
Best possible solution: Same package file split plus TLS builder next to `http.Client` construction, without changing Traefik YAML or CreateConfig.

Do we have a high-confidence way to reproduce? Yes. `go test` on the moved packages passed; CI mock and docker e2e succeeded on 33978900205.

Is this the best way to solve the issue? Yes versus `master`: one job per file, TLS owner is crowdsecconnection, public bag unchanged.

### Evidence
What I checked:
- `go test ./pkg/configuration/ ./pkg/crowdsecconnection/ ./pkg/captcha/ ./pkg/bouncer/` passed (worktree)
- Grep of `*.go` has no `GetTLSConfigCrowdsec` or `configuration.go`
- CI Main Process 33978900213 success; e2e 33978900205 success (GitHub check runs, 2026-09-05T16:48:32Z)

### Rank-up moves
None.
