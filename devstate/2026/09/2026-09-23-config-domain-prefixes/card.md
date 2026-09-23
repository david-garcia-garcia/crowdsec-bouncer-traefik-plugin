## Motivation
Traefik binds operator YAML and labels onto `configuration.Config` through JSON tags. Those tags are the public contract. Three pieces read that struct: the LAPI client, the AppSec listener, and the bouncer.

The tags mix `crowdsec*` (`crowdsecLapiHost`, `crowdsecMode`, `crowdsecLapiTlsCertificateBouncer`), unprefixed router knobs (`enabled`, `captchaSiteKey`, `updateIntervalSeconds`, `redisCacheEnabled`), and one shared `httpTimeoutSeconds`. `enabled` bounces; `crowdsecLapiEnabled` owns the client — the prefix does not say which piece reads the key. Redis connection knobs sit beside `redisCacheUnreachableBlock`, which the bouncer reads. `CertificateBouncer` collides with the bouncer syllable.

An operator who sets `httpTimeoutSeconds: 2` and leaves `crowdsecLapiHttpTimeoutSeconds`, `crowdsecAppsecHttpTimeoutSeconds`, and `captchaSiteverifyHttpTimeoutSeconds` at 0 silently moves all three HTTP clients. The inherit helper treats zero as “use the shared default.”

Left alone, every new knob keeps the mix. Operators keep guessing ownership. A leftover shared timeout keeps coupling three clients that should be independent.

Priority: P2 — real operator pain with a workaround or limited blast radius

## Implementation
Rename every public `Config` JSON tag and matching Go field so the key starts with the piece that reads it (`lapi*`, `appsec*`, `bouncer*`). Drop the `crowdsec` syllable. `logLevel`, `logFormat`, `logFilePath`, and `reclaimGraceSeconds` stay at the root. No old-key aliases and no nested YAML.

The prefix stays on `configuration.Config` and drops at the owning package. `pkg/lapi` identity, ownership, and session now use `scheme` / `host` / `path` / `key`, matching AppSec. Both legs rename `tlsCertificateBouncer` to `tlsClientCertificate` / `tlsClientKey`. `bouncer.New` keeps local names (`enabled`, `lapiFailureAction`, `startupBlock`) and passes `BouncerCaptcha*` into the existing captcha `siteKey` / `secretKey` arguments. `GetVariable` strings are the new Go field names (`LapiKey`, `LapiTLSClientCertificate`); TLS helpers become `Lapi` / `Appsec` plus `TLSCertificateAuthority` / `TLSClientCertificate` / `TLSClientKey`.

Delete `httpTimeoutSeconds` and `EffectiveHTTPTimeoutSeconds`. Each client reads its own knob, default 10, must be `>= 1`: `lapiHttpTimeoutSeconds`, `appsecHttpTimeoutSeconds`, `bouncerCaptchaSiteverifyHttpTimeoutSeconds`. An omitted AppSec scheme or key still copies from LAPI when AppSec is owned; the timeout does not. Validation errors name the new fields.

Reclaim identity JSON reuses the existing LAPI and AppSec marshalers. Dropping the redundant `lapi` prefix and renaming the TLS fields changes the hash; a process restart builds a new client, the same break as the public rename.

README, examples, compose labels, `.traefik.yml` testData, mock and real e2e, and the change-folder specs ship the new names in the same apply.

## What this changes
**Operators.** Rewrite every plugin YAML key and Traefik label to `lapi*` / `appsec*` / `bouncer*`; old names are ignored and `bouncerEnabled` defaults false. A shared `httpTimeoutSeconds: N` becomes `lapiHttpTimeoutSeconds: N` and `appsecHttpTimeoutSeconds: N` (captcha siteverify is `bouncerCaptchaSiteverifyHttpTimeoutSeconds`, default 10).

**Admin users.** None.

**Developers.** `configuration.Config` fields and JSON tags are the new names; `GetVariable` takes those Go field names; `EffectiveHTTPTimeoutSeconds` is deleted; LAPI identity, ownership, and session drop the `lapi` prefix to match AppSec.

**End users.** None.

## Merge readiness
In progress. 0 items remain.

Priority: P2 — real operator pain with a workaround or limited blast radius
Reviewed head: 90327851
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
| Branch | 2026-09-23-config-domain-prefixes pushed | `git` |
| OpenSpec | config-domain-prefixes | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/137 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/changes/archive/2026-09-23-config-domain-prefixes/proposal.md) — modified

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_appsec_bot-detection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_appsec_bot-detection/spec.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_decisionstore_store](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_decisionstore_store/spec.md) — modified
- [core_plugin_lapi_connection](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_lapi_connection/spec.md) — modified
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_lapi_failure-action/spec.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_lapi_reclaim-key/spec.md) — modified
- [core_plugin_lapi_scope-union](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_lapi_scope-union/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-09-23-config-domain-prefixes on branch 2026-09-23-config-domain-prefixes targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/137; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_standards.md) — 7 total, 0 pending, 7 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_nitpicks.md) — 2 total, 0 pending, 2 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_spec.md) — 3 total, 0 pending, 3 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_scope.md) — 1 total, 0 pending, 0 completed, 1 skipped
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-09-23-config-domain-prefixes/devstate/2026/09/2026-09-23-config-domain-prefixes/codereview_coverage.md) — 0 total, 0 pending, 0 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 22 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 90327851c0cb650ea858a23320d518c1979bf4cb | Card must match the branch you measured |

### Stored data model
- `redis` — DecisionStore SessionHex key prefix. field `lapiScheme` renamed to `scheme`. migration: missing
- `redis` — DecisionStore SessionHex key prefix. field `lapiHost` renamed to `host`. migration: missing
- `redis` — DecisionStore SessionHex key prefix. field `lapiPath` renamed to `path`. migration: missing
- `redis` — DecisionStore SessionHex key prefix. field `lapiKey` renamed to `key`. migration: missing
