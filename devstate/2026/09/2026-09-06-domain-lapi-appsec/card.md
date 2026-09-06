Developer review: in progress — 2026-09-06T12:39:22Z

## What this changes
**Operators.** None versus `master` yet (OpenSpec + usage Language only). Live Redis prefix will change once the apply lands.

**Admin users.** None.

**Developers.** OpenSpec change `separate-lapi-appsec-packages`: `pkg/lapi` + `pkg/appsec`, Bouncer holds both reclaim pointers. Specs added `core_plugin_lapi_connection` and `core_plugin_appsec_client`.

**End users.** None.

## Motivation
On `master`, `pkg/crowdsecconnection` is one reclaim type for CrowdSec LAPI decisions and AppSec WAF. Developers cannot change one job without reading the other, and spec `core_plugin_connection_source-files` still forbids a new import path. Without this work, later LAPI and AppSec changes keep landing in the same type.

## Merge readiness
Propose is apply-ready; product code is not landed. Implement remains.

Priority: P3 — internal package clarity, no current operator or user harm
Reviewed head: c84e835
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Propose ready; product apply not started |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032980438 |
| Local tests proof | N/A | `localTests: none` (before implement) |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-domain-lapi-appsec pushed | `git` |
| OpenSpec | separate-lapi-appsec-packages | `openspec/changes/separate-lapi-appsec-packages/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/26 | pr-host |
| CI | build 34032980438 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34032980438 | pr-host CI |
| Local tests | none | handoff.yaml |
| PR comments | no comments | get_comments |

## Specs
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — added
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — added
- [core_plugin_middleware_instance-reclaim](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — modified
- [core_plugin_connection_source-files](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — modified
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-06-domain-lapi-appsec/openspec/changes/separate-lapi-appsec-packages/proposal.md) — modified

## Follow-up issues
- [ ] [take] [small] Spec `core_plugin_connection_source-files` → lapi + appsec package-layout specs — catalog folder still exists until archive. Not taken: archive sync.

## How this fits together
Agreed explore → OpenSpec `separate-lapi-appsec-packages` on PR 26. Implement next.

## Decision needed
None.

## Before merge
- [ ] Implement `pkg/lapi` and `pkg/appsec`
- [x] Explore decisions resolved
- [x] Propose apply-ready

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 5 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | c84e835d1b4e8583020266b426462865c7e4d406 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Two packages and two reclaim keys versus the mixed `CrowdsecConnection` on `master`.

Do we have a high-confidence way to reproduce? Yes — `pkg/crowdsecconnection/connection.go` still holds both clients on `master`.

Is this the best way to solve the issue? Yes — agreed in explore.

### Evidence
What I checked:
- `openspec status --change separate-lapi-appsec-packages` 4/4 complete
- CI run 34032980438 succeeded (GitHub MCP)

### Rank-up moves
None.
