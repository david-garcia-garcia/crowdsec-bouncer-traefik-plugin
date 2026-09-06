Developer review: in progress — 2026-09-06T13:11:26Z

## What this changes
**Operators.** Live/none Redis cache keys use prefix `lapi:` and no longer hash AppSec host/key/TLS (one-time miss on upgrade). Plugin JSON/YAML keys are unchanged. Lifecycle logs stay `crowdsec connection started|sleeping|waking|closed`.

**Admin users.** None.

**Developers.** `pkg/crowdsecconnection` is now `pkg/lapi` (`lapi.Client`) plus `pkg/appsec` (`appsec.Client`). Bouncer holds `lapiClient` and `appsecClient`. Neither package imports the other. `crowdsecMode: appsec` skips LAPI Open.

**End users.** None.

## Motivation
On `master`, `pkg/crowdsecconnection` is one reclaim type for CrowdSec LAPI decisions and AppSec WAF. Developers cannot change one job without reading the other, and spec `core_plugin_connection_source-files` still forbids a new import path. Without this work, later LAPI and AppSec changes keep landing in the same type.

## Merge readiness
Apply landed and CI succeeded. Code review of the apply diff remains. 1 item remains.

Priority: P3 — internal package clarity, no current operator or user harm
Reviewed head: 5123527
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | CI succeeded; no open PR comments |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34035078833 |
| Local tests proof | N/A | `prHost` remote; CI covers |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-06-domain-lapi-appsec pushed | `git` |
| OpenSpec | separate-lapi-appsec-packages | `openspec/changes/separate-lapi-appsec-packages/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/26 | pr-host |
| CI | build 34035078833 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/34035078833 | pr-host CI |
| Local tests | passed | handoff.yaml |
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
Local ticket on branch `2026-09-06-domain-lapi-appsec`, OpenSpec `separate-lapi-appsec-packages`, PR 26. Apply is on HEAD `5123527`; CI Main Process succeeded.

## Decision needed
None.

## Before merge
- [ ] Code review of the apply diff
- [x] Implement `pkg/lapi` and `pkg/appsec`
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
| Reviewed head | 51235275d777b05ce8fb54eec6b278e1b92fbce3 | Card must match the branch you measured |

### Stored data model
- Changed: Redis `keyPrefix` / `lapi.CachePrefix` — string — sample `crowdsecconnection:<hex>` → `lapi:<hex>` (live identity dropped AppSec host/key/TLS). Upgrade: old keys not rewritten; one-time miss.

### Technical review
Best possible solution: Two packages and two reclaim keys versus the mixed `CrowdsecConnection` on `master`.

Do we have a high-confidence way to reproduce? Yes — `pkg/crowdsecconnection/connection.go` still holds both clients on `master`.

Is this the best way to solve the issue? Yes — agreed in explore; types are both `Client`.

### Evidence
What I checked:
- `go test ./pkg/lapi/ ./pkg/appsec/ ./pkg/bouncer/ .` passed (skip Windows logging TempDir cleanup)
- CI Main Process 34035078833 succeeded; e2e 34035078830 succeeded (GitHub MCP get_check_runs)

### Rank-up moves
None.

[sgsi-dev-ticket-status:2026-09-06-domain-lapi-appsec]
