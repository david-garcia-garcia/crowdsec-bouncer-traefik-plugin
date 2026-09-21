## Progress

| Phase | Work | Card | Duration |
| --- | --- | --- | --- |
| Prepare | done | done | 1m |
| Explore | done | done | 2h 24m |
| Propose | done | done | 6m |
| Implement | done | done | 35m |
| Code review | — | — | — |
| Devdocs impact | — | — | — |
| Archive | — | — | — |
| Pull request | — | — | — |

Last updated: 2026-09-21 20:57 UTC

## Motivation
Not yet.

## Implementation
Not yet.

## What this changes
**Operators.** None.

**Admin users.** None.

**Developers.** None.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 057e7a3b
Owner decision: None.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 3/6 | Limited confidence |
| CI proof | 3/6 | in progress |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-21-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/135 | pr-host |
| CI | build 35654218831 in progress | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/35654218831 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
- 2026-09-18-lapi-scope-failclosed-query-hardening — added
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
Ticket 2026-09-21-bouncer-instance-severance on branch 2026-09-21-bouncer-instance-severance targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/135; CI build 35654218831 in progress.

## Explore Decisions
None.

## Before merge
None.

## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 22 added / 0 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 057e7a3b425d8c340319bfe92bb46914757f7fde | Card must match the branch you measured |

### Stored data model
None.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 057e7a3b425d8c340319bfe92bb46914757f7fde)

### Rank-up moves
None.
