## Motivation
Each Traefik CrowdSec middleware `New` does three jobs at once: open a LAPI client (stream / live / none / alone), open an AppSec client when `crowdsecAppsecEnabled` is true, and bounce that router’s requests with those clients. Sharing already exists, but only as an identity hash (LAPI URL+key; AppSec listener+key+bodyLimit). There is no operator-chosen name.

Every bouncing router must copy the full LAPI/AppSec YAML. Create-time knobs are first-wins. `decisionScopeHeaders` unions into stream `scopes=` from whoever constructed first. Traefik does not guarantee constructor order, so a bouncing router can `New` before the middleware that opens the shared clients.

Left alone, operators cannot keep per-route bounce policy (remediation header, failure action, captcha, trusted IPs) while sharing one named LAPI/AppSec pair. They keep duplicating secrets and fetch knobs, and they cannot attach a subscriber-only route without also owning a backend.

Priority: P2 — real operator pain with a workaround (copy the full YAML on every router)

## Implementation
`plugin.go` severs the three jobs on one middleware: `crowdsecLapiEnabled` / `crowdsecAppsecEnabled` own a client (`Open` then `instance.PublishAll`); `enabled` plus a set instance name subscribes. `pkg/instance` holds two process-wide slot tables (LAPI vs AppSec). Publish fans out into Yaegi-safe `atomic.Value`s; Subscribe never waits. The bouncer `ServeHTTP` only Loads those fields. Ownership Open is the middleware name plus that client’s knobs (`lapi.OwnershipKey`, AppSec `Key(cfg, name)`); DecisionStore stays `SessionHex`. `streamStartupBlock` is a request-path published check, not a wait in `New` or `startStream`. A taken name rejects under one mutex and rolls back any slot that attempt already wrote; subscribers do not Bind reclaim.

## What this changes
**Operators.** Existing installs must set `crowdsecLapiEnabled: true` on every middleware that opens LAPI (default is false, so an unchanged YAML stops owning LAPI). `crowdsecMode: appsec` is rejected; AppSec-only is `crowdsecLapiEnabled: false` plus `crowdsecAppsecEnabled: true`. They can publish and subscribe with `crowdsecLapiInstanceName` / `crowdsecAppsecInstanceName`, set opener-only `crowdsecLapiStreamScopes`, and optionally `reclaimGraceSeconds`. `streamStartupBlock: true` now returns 503 until subscribed clients are published, not until the first stream poll. Watch `crowdsec instance name taken`, `crowdsec lapi stream collision`, `crowdsec bouncer backend missing`, and lifecycle `crowdsec lapi/appsec instance started|sleeping|waking|closed` plus `crowdsec bouncer bound|unbound`.
**Admin users.** None.
**Developers.** Public config adds `crowdsecLapiEnabled`, instance names, `crowdsecLapiStreamScopes`, and `reclaimGraceSeconds`; drop `AppsecMode`. `bouncer.New` no longer takes `*lapi.Client` / `*appsec.Client` — clients arrive via `LAPIBinding` / `AppSecBinding`. LAPI Open uses `OwnershipKey`; AppSec Open key includes the middleware name. Stream `scopes=` is the opener list, not a live header-map union. Two middleware names on the same `SessionHex` may share a DecisionStore and are two Clients. A second stream owner on the same host+key logs WARN and still succeeds `New`.
**End users.** None.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real operator pain with a workaround (copy the full YAML on every router)
Reviewed head: 07b653d4
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 1/6 | Not ready |
| CI proof | 1/6 | not seen |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | N/A | no OPEN PR |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-09-22-bouncer-instance-severance pushed | `git` |
| OpenSpec | bouncer-instance-severance | `openspec/` |
| Pull request | none | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/changes/archive/2026-09-22-bouncer-instance-severance/proposal.md) — added

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_lapi_reclaim-key/spec.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_lapi_scope-union/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/openspec/specs/core_plugin_middleware_instance-slots/spec.md) — added

## Deviations from the ask
- taken:  →  — `` — requirement F3 / T2 subscriber sketch set `crowdsecLapiEnabled: true` with no key, which `ValidateParams` rejects because a true owner flag must Open. Built: `enabled: true`, owner flags false, instance names set (Open-vs-subscribe table).. Requester: not asked.

## Follow-up issues
- [ ] [Stream startup block still means more than "published"](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/knowledge/debt/2026-09-22-stream-startup-block-rethink.md) — `streamStartupBlock` still names stream startup while ready means subscribed client published.

## How this fits together
Ticket 2026-09-22-bouncer-instance-severance on branch 2026-09-22-bouncer-instance-severance targeting master; PR no PR yet; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Which package owns the dual LAPI/AppSec slot tables and Publish/Subscribe API? | additive asked — new subsystem in scope (“Named LAPI and AppSec slots”, Late bind); criterion names publish/subscribe | assumed — `pkg/instance` owns both slot tables and Publish/Subscribe/Clear; `plugin.go` orchestrates only; tests colocated under that package. | implement |

## Before merge
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_standards.md) — 14 total, 0 pending, 10 completed, 4 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_nitpicks.md) — 3 total, 0 pending, 3 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_spec.md) — 5 total, 0 pending, 1 completed, 4 skipped
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_dead.md) — 5 total, 0 pending, 0 completed, 5 skipped
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-22-bouncer-instance-severance/devstate/2026/09/2026-09-22-bouncer-instance-severance/codereview_coverage.md) — 4 total, 0 pending, 0 completed, 4 skipped

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 12 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 07b653d41a2b2b6f05bf58f3e830bc096c879dca | Card must match the branch you measured |

### Stored data model
**Changed**
- DecisionStore `SessionHex` field `defaultDecisionSeconds` (int64): sample `60` → `5` forks the store (I2). Upgrade: old keys not rewritten; next Open uses the new hash.
- DecisionStore `SessionHex` field `streamScopes` (string list, stream mode only): omitted/empty both hash as `ip,range`; extras such as `country` change the hex. Upgrade: old keys not rewritten; new store sends `startup=true`.
- DecisionStore `SessionHex` field `redis` (object: `host`, sorted `readHosts`, `password`, `database`): hashed only when `redisCacheEnabled` is true. Sample when false: leftover host `redis:6379` and password `secret` keep the same hex (S1). Sample when true: host `redis-a:6379` → `redis-b:6379` is a new store (S3). Upgrade: old keys not rewritten; leftover Redis fields no longer fork a disabled cache.

### Technical review
Best possible solution: Not yet.

Do we have a high-confidence way to reproduce? Not yet.

Is this the best way to solve the issue? Not yet.

### Evidence
What I checked:
- assembled from the run bus (`deliver_card`, 07b653d41a2b2b6f05bf58f3e830bc096c879dca)

### Rank-up moves
None.
