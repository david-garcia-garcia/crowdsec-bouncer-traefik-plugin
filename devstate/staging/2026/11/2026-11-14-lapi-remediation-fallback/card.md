## Motivation
CrowdSec LAPI decisions carry a free-text `type`. The plugin knows how to remediate two of them, `ban` and `captcha`. Fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198), following upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402) and upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), made every other type (for example `throttle` or `challenge`) ingest as a ban, on stream New (Ip, header-mapped scopes, Range) and in the live/none pick. That fails closed, but the operator has no choice: the CrowdSec bouncer spec defines a `remediation_fallback` (ignore / ban / captcha) for exactly this case, and official bouncers let the operator choose (lua-cs-bouncer `FALLBACK_REMEDIATION`; cs-firewall-bouncer applies only its `supported_decisions_types` and ignores other types on add and delete).

A second gap sits on the delete path. Stream Deleted rows never read the type, so a Deleted row of a type the plugin does not remediate still drops whatever the Ip slot or Range CIDR holds. Reproduced in explore: tick 1 stores a ban for `203.0.113.7` and for `10.0.0.0/8`; tick 2 sends only Deleted rows of type `throttle` for the same Ip and CIDR; both bans are gone. There was no setting that makes such a row a no-op.

Upstream PR #433 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433) proposes the opposite answer for one type name: treat `whitelist` decisions as an allow that lifts bans. This fork's own debt note carried the same allow-as-veto idea. That model is wrong. WHITELIST or ALLOW are not valid CrowdSec decisions, and using decisions to allow traffic is an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW. The LAPI swagger defines `type` as "'ban', 'captcha' or something custom", and no CrowdSec component gives `whitelist` or `allow` allow semantics. Allowing traffic is done upstream by parser whitelists and LAPI allowlists (`cscli allowlists`), which stop or expire decisions at the source.

Left alone, operators who run custom types must accept every one as a ban, an unknown-type delete can lift a real ban, and the pressure to special-case `whitelist` as an allow (upstream #433) stays open.

Priority: P2 — operators get no choice for unknown decision types and an unknown-type delete can clear a real ban; the default still fails closed, so the blast radius is limited

## Implementation
One public knob, `lapiRemediationFallback` (`ban` | `captcha` | `ignore`, default `ban`, empty treated as `ban`), validated as an enum in `ValidateParams`. It lives on the LAPI connection: `lapi.New` reads it from the middleware that opens the connection and holds the effective value on `lapi.Client`; a subscriber's value is unused, as for `lapiStreamScopes`.

The policy stays at LAPI ingest. `ingestRemediationKind` keeps `ban` / `captcha` unchanged and maps every other type to the fallback letter (`t`, `c`) or to empty under `ignore`, TRACE-logging `handleStreamCache:unknownType` with `type` and `fallback`. Every ingest site reads empty as "not stored": `streamPutItem` (Ip and header scopes), the Range New branch, and the live/none strongest pick, so an IP whose only decisions are unknown-type passes under `ignore`. One `Client` predicate, `deletedTypeClearsStore`, guards both Deleted shapes (Ip/header and Range): under `ignore` an unknown-type Deleted row deletes nothing; under `ban` / `captcha` it keeps the whole-slot delete (the existing multi-decision-per-key debt). Skipped rows do not count in the poll counters. No type name is special-cased; `whitelist` and `allow` follow the knob like `throttle`.

The effective value enters the Client ownership key and, only when it is not `ban`, the `SessionHex` store identity (`omitempty`). A change of value opens a new Client and a new DecisionStore that refills from LAPI; default deployments keep their `SessionHex` and Redis keys on upgrade. README (Decisions paragraph and Variables entry), usage devdocs and the debt note carry the whitelist / allow position; the debt note loses its allow-as-veto framing and keeps the real multi-decision debt.

Process note: this run used the OpenDev CLI (`opd-mcp/scripts/cli.mjs`) instead of the OpenDev MCP, the GitHub MCP for PR operations, and Claude Code subagents without the configured grok model slug. The code review walked the ten axes in the reviewing agent itself, not as ten parallel subagents.

## What this changes
**Operators.** New optional key `lapiRemediationFallback` (`ban` default, `captcha`, or `ignore`) on the middleware that connects to LAPI decides what happens to decision types other than `ban` and `captcha`; changing it from `ban` forks the decision store, which refills from LAPI, and it is separate from `bouncerLapiFailureAction`.
**Admin users.** None.
**Developers.** `whitelist` / `allow` decisions are not an allow anywhere in the plugin and no type name may be special-cased; unknown types go only through `lapiRemediationFallback`.
**End users.** None.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — operators get no choice for unknown decision types and an unknown-type delete can clear a real ban; the default still fails closed, so the blast radius is limited
Reviewed head: fb1056c3
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43636993224 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-11-14-lapi-remediation-fallback pushed | `git` |
| OpenSpec | lapi-remediation-fallback | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/205 | pr-host |
| CI | build 43636993224 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43636993224 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43636993224 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/archive/2026-11-14-lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/archive/2026-11-14-lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/archive/2026-11-14-lapi-remediation-fallback/proposal.md) — modified
- [core_plugin_lapi_remediation-fallback](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/changes/archive/2026-11-14-lapi-remediation-fallback/proposal.md) — added

Completed:
- [core_plugin_decisions_scopes](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/specs/core_plugin_decisions_scopes/spec.md) — modified
- [core_plugin_lapi_origin-based-decision-remap](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/specs/core_plugin_lapi_origin-based-decision-remap/spec.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/specs/core_plugin_lapi_reclaim-key/spec.md) — modified
- [core_plugin_lapi_remediation-fallback](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/openspec/specs/core_plugin_lapi_remediation-fallback/spec.md) — added


## Deviations from the ask
None.

## Follow-up issues
None.

## How this fits together
Ticket 2026-11-14-lapi-remediation-fallback on branch 2026-11-14-lapi-remediation-fallback targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/205; CI build 43636993224 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43636993224.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Where do README, devdocs and the delivery card state the position on `whitelist` / `allow` decisions, and with which references? | additive asked — new documentation text; requirement Desired 5 and "Delivery card (must)" | assumed — README: one paragraph under "## Decisions" (after the scope list) plus the `LapiRemediationFallback` Variables entry, which also says it is not `bouncerLapiFailureAction`. Devdocs: the stream-apply and origin-remap packets. Card: codereview's Delivery axis writes it into `codereview_delivery.md` `## Motivation`. Text in all three: `whitelist` and `allow` are not valid CrowdSec decision types and are an inadequate way to manage whitelists, because the LAPI stream is designed to say WHAT TO BLOCK, not WHAT TO ALLOW; use parser whitelists or LAPI allowlists (`cscli allowlists`). References: upstream issue #402 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/402), upstream PR #403 point 1 (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/403), upstream PR #433 whitelist part (https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/433), fork PR #198 (https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/198). Source: requirement.md; human, chat 2026-11-14. Implement wrote the README paragraph (under "## Decisions", after the scope list and header mapping) and the Variables entry, and the same statement in `knowledge/devdocs/core_plugin_lapi_stream-apply.md` and `core_plugin_lapi_origin-based-decision-remap.md`; the card Motivation stays with codereview's Delivery axis. | implement |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_standards.md) — 0 total, 0 pending, 0 completed
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_spec.md) — 0 total, 0 pending, 0 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_security.md) — 0 total, 0 pending, 0 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-14-lapi-remediation-fallback/devstate/staging/2026/11/2026-11-14-lapi-remediation-fallback/codereview_coverage.md) — 2 total, 0 pending, 1 completed, 1 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 6 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | fb1056c3b6ca9166ff5e458b4b6757214b1ed0d1 | Card must match the branch you measured |

### Stored data model
- DecisionStore (memory `ttl_map` and Redis, key prefix `SessionHex`): no new key, table, or field. The stream session payload hashed into `SessionHex` gains `remediationFallback` (`omitempty`, filled only when the effective `lapiRemediationFallback` is not `ban`). Omitted, empty, or `ban` keeps the pre-knob `SessionHex` and Redis key prefix; `captcha` or `ignore` forks to a new prefix that refills from LAPI with `startup=true`, and the old keys expire by TTL. No migration needed (derived identity, not a schema).
