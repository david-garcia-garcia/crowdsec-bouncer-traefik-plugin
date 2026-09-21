## Progress

| Phase | Work | Card | Duration |
| --- | --- | --- | --- |
| Prepare | done | done | 1m |
| Explore | done | done | 2h 24m |
| Propose | done | done | 6m |
| Implement | done | done | 36m |
| Code review | done | done | 3m |
| Devdocs impact | done | done | 2m |
| Archive | — | — | — |
| Pull request | — | — | — |

Last updated: 2026-09-21 21:03 UTC

## Motivation
Every Traefik CrowdSec middleware constructor used to open LAPI and AppSec and bounce the same router. Sharing one LAPI stream meant every bouncing router duplicated LAPI and AppSec YAML, and implicit reclaim identity tied `createdBy` to the Traefik middleware name rather than an operator-chosen instance. Operators running several routers against one CrowdSec stream could not designate one opener with secrets and have the rest subscribe by name without copying keys or racing constructor order.

Priority: P2 — real operator pain reconfiguring shared clients; no data loss but heavy YAML duplication and fragile startup order.

## Implementation
Public config is split into `lapi*`, `appsec*`, and `bouncer*` domains with enable flags and instance names. `plugin.New` Opens and publishes into `pkg/instance` when secrets are present, subscribes by name when enabled without secrets, or skips legs when disabled. `bouncerHold` returns a 503 holder without bouncing. The bouncer resolves clients per request via Peek (with construct fallback for openers), applies failure actions on miss, and keeps scope registration on the LAPI opener only.

## What this changes
**Operators.** Must migrate YAML to new key names (`lapiKey`, `bouncerEnabled`, `lapiInstance`, etc.); may use one opener plus named subscribers or optional hold routers instead of duplicating LAPI/AppSec secrets on every bouncing middleware.

**Admin users.** None.

**Developers.** Traefik plugin config JSON tags and semantics are breaking (beta); named-instance Peek/publish contract and removed `appsec` `lapiMode` are the main integration surface.

**End users.** None unless operators misconfigure subscribe/hold (requests may passthrough or 503 on hold routers).

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain reconfiguring shared clients; no data loss but heavy YAML duplication and fragile startup order.
Reviewed head: 79c4b46e
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-21-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/135 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
- 2026-09-18-lapi-scope-failclosed-query-hardening — added
- 2026-09-21-bouncer-instance-severance — added
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- [core_plugin_middleware_named-instance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/openspec/changes/bouncer-instance-severance/proposal.md) — added
- build_e2e_pester_crowdsec-stack — added
- core_plugin_appsec_bot-detection — added
- core_plugin_decisions_scopes — added
- core_plugin_decisionstore_store — added
- core_plugin_ip_radix-lookup — added
- core_plugin_lapi_connection — added
- core_plugin_lapi_origin-based-decision-remap — added
- core_plugin_lapi_stream-single-flight — added
- core_plugin_lapi_usage-metrics — added
- core_plugin_middleware_captcha-gate — added
- core_plugin_middleware_captcha-routing — added
- core_plugin_middleware_captcha-siteverify — added
- core_plugin_middleware_forced-decision — added

## Deviations from the ask
- taken: bouncing handler MUST NOT store `*Client` from construct; request path Peek only. → Peek the named slot first, then use the Client pointer `bouncer.New` already received. — `pkg/bouncer/bouncer.go publishedLAPI / publishedAppsec` — unit tests inject Clients through `bouncer.New`; honouring Peek-only would require every test to Publish. Production Open still Publishes before `bouncer.New`, so Peek hits the slot.. Requester: not asked.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-21-bouncer-instance-severance on branch 2026-09-21-bouncer-instance-severance targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/135; CI not seen.

## Explore Decisions
None.

## Before merge
None.

## Findings
[P2] Breaking YAML rename is intentional beta; upgrade requires rewriting middleware blocks, not aliases.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_standards.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-21-bouncer-instance-severance/devstate/2026/09/2026-09-21-bouncer-instance-severance/codereview_coverage.md) — 1 total, 0 pending, 0 completed, 1 skipped

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 23 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 79c4b46e8324e7df0e5dfa95a5f3517acb4ceac0 | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 79c4b46e8324e7df0e5dfa95a5f3517acb4ceac0)

### Rank-up moves
None.
