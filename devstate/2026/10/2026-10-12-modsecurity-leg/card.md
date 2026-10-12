## Motivation
The reclaim table already binds three groups: LAPI, AppSec, and captcha. `plugin.go` names `legLAPI`, `legAppSec`, `legCaptcha` only. There is no ModSecurity group, no `pkg/modsecurity`, and no `modsec*` keys. Operators who want OWASP CRS inspect still load `david-garcia-garcia/traefik-modsecurity` as a second Traefik plugin. README Traefik Security still lists that sibling as a separate middleware.

AppSec `Query` applies `bouncerAppsecFailureAction` on every unreachable, 5xx, or unreadable miss. The packaged default is `ban`. There is no admission gate, so a down AppSec listener keeps banning every later request. `passthrough` already exists as a per-request workaround without back-off. AppSec Sleep/Wake are reclaim hooks, not request skip.

Left alone, a down AppSec takes ingress down for the life of the outage unless someone remembers `passthrough`, and CRS stays a second plugin with a second config surface for the same allow-or-block inspect job. The source plugin's real Pester families (allow, CRS path-traversal block, body-size, deny-verbs, failMode, backoff) are also absent from this tree's real e2e.

Priority: P2 — real operator pain with a workaround and limited blast radius

## Implementation
A fourth reclaim group `modsec` copies the captcha-leg own-vs-bounce pattern: `modsecEnabled` Opens and publishes; `bouncerEnabled` plus a non-empty `modsecInstanceName` Watches; claim failure rolls this group back with the others. The new reclaim Client copies the inbound request to absolute `modsecUrl`, classifies sidecar 2xx as allow, copies 3xx/4xx as the visitor block without following redirects, and treats 5xx or transport as a WAF miss. Per-router `bouncerModsecFailMode` (`open` default, `close` empty HTTP 502) sits on the Bouncer; utilities `backendbackoff.Gate` sits on the shared Client (ModSec period default 0, so the gate is off until set). ServeHTTP runs ModSec after AppSec; trusted clients skip LAPI, AppSec, and ModSec; `bypassModsec` skips only CRS, and `bypass` now skips all three inspect legs. Deny-verbs and `modsecBodyLimit` (omitted 8 MiB, `0` unlimited) run before the gate.

The same Gate is imported onto the AppSec Client. Omitted `appsecUnhealthyBackOffPeriodSecs` is 30, so after the trip later requests skip AppSec and do not apply FailureAction; admitted misses still use `bouncerAppsecFailureAction` (default `ban` unchanged). Those knobs join the AppSec ownership key. An AppSec gate skip continues to ModSec when that leg is subscribed. README documents the ModSec leg and drops the sibling-plugin listing. Real e2e adds Pester domain `modsec` with an inspect-only Apache CRS sidecar and the mapped source families.

## What this changes
**Operators.** New own-axis `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, and per-router `bouncerModsecFailMode`; omitted AppSec backoff is 30s skip-after-trip (set `appsecUnhealthyBackOffPeriodSecs: 0` to keep per-request FailureAction). `modSecurityUrl` does not bind. `bypass` now also skips ModSec.
**Admin users.** None.
**Developers.** `bouncer.New` takes a fourth subscribe flag; reclaim group `modsec`; action token `bypassModsec` and `ActionMatch.SkipModsec`; AppSec `ErrGateSkip` means the hop was skipped and FailureAction must not run; remediation header value `ban:modsec`.
**End users.** After AppSec trips unhealthy under the new default gate, later visitors are no longer banned solely because AppSec is down. When operators enable ModSec, sidecar 3xx/4xx becomes a visitor-facing block.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain with a workaround and limited blast radius
Reviewed head: 929440b6
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38304409944 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-12-modsecurity-leg pushed | `git` |
| OpenSpec | modsecurity-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190 | pr-host |
| CI | build 38304409944 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38304409944 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38304409944 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — added
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/proposal.md) — added

Completed:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_instance-slots/spec.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_modsecurity_client/spec.md) — added
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_modsecurity_inspect/spec.md) — added


## Deviations from the ask
- taken: absorb traefik-modsecurity (its public YAML keys). → dest naming family `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, `bouncerModsecFailMode` (same stems as `appsec*` / `lapi*` / `captcha*`). — `pkg/configuration/configuration.go` — honouring the source key names would add a second naming family next to the dest public surface.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-12-modsecurity-leg on branch 2026-10-12-modsecurity-leg targeting 2026-10-04-bouncer-refactor; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190; CI build 38304409944 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38304409944.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| How does a fourth leg bind (instance name, reclaim, subscribe) once designed? | bounded asked — changes existing `plugin.go` open/claim/Watch and `bouncer.New` (1 file + 1 constructor; three existing legs enumerated); Desired "A new ModSecurity leg alongside LAPI, AppSec, and captcha" | assumed — copy the dest pattern. Group `modsec`, alias `alias:modsec:<name>`, `modsecEnabled` owns, `bouncerEnabled` + non-empty `modsecInstanceName` subscribes, `Open` + `SetAlias` + `Watch` + `ReceiveModSec`. Exclusive publish and multi-leg rollback include this group (captcha-claim failure also `ClearPublisher` modsec). JSON stems `modsec*` (dest `appsec*`/`lapi*`/`captcha*`), not the source plugin's `modSecurityUrl` camelCase. | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_standards.md) — 6 total, 0 pending, 5 completed, 1 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_nitpicks.md) — 8 total, 0 pending, 8 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_security.md) — 1 total, 0 pending, 1 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/devstate/2026/10/2026-10-12-modsecurity-leg/codereview_coverage.md) — 7 total, 0 pending, 6 completed, 1 skipped


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 4 added / 12 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 929440b6acabde949e08579edbad8d8c0c679724 | Card must match the branch you measured |

### Stored data model
None.
