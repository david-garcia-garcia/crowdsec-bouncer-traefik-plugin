Developer review: in progress — 2026-09-05T16:28:12Z

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None. Product code versus `master` is unchanged; explore recorded file-split and TLS-move decisions only.

**End users.** None.

## Motivation
On `master`, `pkg/configuration/configuration.go` holds the Traefik Config DTO, enums, file secrets, template compile, validation, and runtime LAPI/AppSec TLS construction in one 600-line file. Leaving it mixed keeps the TLS builder in the config bag instead of next to the HTTP clients that use it, so later edits keep touching five jobs at once.

## Merge readiness
Not ready for review. 1 item remains.

Priority: P3 — Spec, docs, tests, or internal clarity — no current user or operator harm
Reviewed head: ee1cdff
Owner decision: Required. See Decision needed.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Explore done; apply not started; one CI job still running |
| CI proof | 3/6 | Main Process and mock e2e succeeded; docker e2e in progress |
| Local tests proof | N/A | Before implement; remote CI is the proof axis |
| Review resolution | 6/6 | No OPEN PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-05-split-configuration-files pushed | git |
| OpenSpec | none | openspec/ |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/17 | GitHub MCP |
| CI | build 33977872802 in progress https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/33977872802 | GitHub check runs |
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
Explore decided sibling file names and an unexported TLS builder in `pkg/crowdsecconnection`. Stub PR 17 remains the card host. Apply has not started.

## Decision needed
| Question | Decision | By |
| --- | --- | --- |
| Exact sibling file names (`config.go` vs keeping `configuration.go`)? | assumed — `config.go` (DTO + New + enums), `secrets.go`, `template.go`, `validate.go`. Remove `configuration.go` after the split. | explore |
| `mode.go` or constants file for enums? | assumed — keep the const block in `config.go`. Ticket names were examples. | explore |
| Does `GetTLSConfigCrowdsec` stay exported after the move? | assumed — no. Unexport in `pkg/crowdsecconnection`. | explore |
| Do TLS tests stay in `configuration_test.go`? | assumed — no. Move `Test_GetTLSConfigCrowdsec` and `validPEM` with the symbols. | explore |
| Should HTTP client construction move into `tls.go` as well? | assumed — no. Sibling owns connection.go splits. | explore |
| Does `validateParamsTLS` move with the runtime builder? | assumed — no. It is ValidateParams, not client TLS. | explore |
| Which spec leaf hosts the file-owner and TLS-builder requirements? | assumed — new `core_plugin_config_file-owners` (FindSpecHost at propose). | explore |

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
| Reviewed head | ee1cdff702d3785292fd3af0c64edff4cafd98f1 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not applied yet versus `master`. Explore chose `config.go`/`secrets.go`/`template.go`/`validate.go` and `crowdsecconnection/tls.go` (unexported).

Do we have a high-confidence way to reproduce? Yes, mixed `configuration.go` and `GetTLSConfigCrowdsec` call sites are on `master` at `2d4acf3`.

Is this the best way to solve the issue? Not applied yet; file owners match One job, one owner without changing Traefik JSON or CreateConfig.

### Evidence
What I checked:
- Explore written (`devstate/.../explore.md`, ee1cdff)
- CreateConfig stays on `plugin.go` (Yaegi research packet)
- CI: Main Process success, mock e2e success, docker e2e in progress (check runs, 2026-09-05T16:28Z)

### Rank-up moves
None.
