Developer review: in progress — 2026-09-05T16:32:00Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** OpenSpec change `split-configuration-files` adds spec `core_plugin_config_file-owners`. Go file split is not applied yet versus `master`.

**End users.** None.

## Motivation
On `master`, `pkg/configuration/configuration.go` holds the Traefik Config DTO, enums, file secrets, template compile, validation, and runtime LAPI/AppSec TLS construction in one 600-line file. Leaving it mixed keeps the TLS builder in the config bag instead of next to the HTTP clients that use it, so later edits keep touching five jobs at once.

## Merge readiness
Not ready for review. 1 item remains.

Priority: P3 — Spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: 9b3ed0e
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Proposal is apply-ready; Go apply not started; docker e2e still running |
| CI proof | 3/6 | Main Process and mock e2e succeeded; docker e2e in progress |
| Local tests proof | N/A | Before implement; remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-split-configuration-files pushed | git |
| OpenSpec | split-configuration-files | openspec/changes/split-configuration-files/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/17 | GitHub MCP |
| CI | build 33978016024 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33978016024 | GitHub check runs |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | pull_request_read |
| Security | None. | not reviewed yet |
| Performance | None. | not reviewed yet |
| Dead | None. | not reviewed yet |

## Specs
- [core_plugin_config_file-owners](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-05-split-configuration-files/openspec/changes/split-configuration-files/proposal.md) — added

## Follow-up issues
None.

## How this fits together
Propose created apply-ready OpenSpec artifacts on PR 17. Implement has not started.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Exact sibling file names (`config.go` vs keeping `configuration.go`)? | assumed — `config.go` (DTO + New + enums), `secrets.go`, `template.go`, `validate.go`. Remove `configuration.go` after the split. | explore |
| `mode.go` or constants file for enums? | assumed — keep the const block in `config.go`. Ticket names were examples. | explore |
| Does `GetTLSConfigCrowdsec` stay exported after the move? | assumed — no. Unexport in `pkg/crowdsecconnection`. | explore |
| Do TLS tests stay in `configuration_test.go`? | assumed — no. Move `Test_GetTLSConfigCrowdsec` and `validPEM` with the symbols. | explore |
| Should HTTP client construction move into `tls.go` as well? | assumed — no. Sibling owns connection.go splits. | explore |
| Does `validateParamsTLS` move with the runtime builder? | assumed — no. It is ValidateParams, not client TLS. | explore |

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
| Specs in this PR | 1 added / 0 modified | Same list as Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 9b3ed0ed2ed41df7f5f27cc1e1803cef2f0dd16b | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied in Go yet versus `master`. Proposal splits configuration files and moves TLS construction into `pkg/crowdsecconnection`.

Do we have a high-confidence way to reproduce? Yes, mixed `configuration.go` is on `master` at `2d4acf3`.

Is this the best way to solve the issue? The proposal matches One job, one owner without changing Traefik JSON or CreateConfig.

### Evidence
What I checked:
- `openspec validate split-configuration-files --type change --strict` passed (9b3ed0e)
- FindSpecHost new `core_plugin_config_file-owners` (devstate/specs.md)
- CI: Main Process success, mock e2e success, docker e2e in progress (check runs, 2026-09-05T16:32Z)

### Rank-up moves
None.
