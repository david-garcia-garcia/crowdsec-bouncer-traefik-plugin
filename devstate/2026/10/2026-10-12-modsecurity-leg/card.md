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
Ready for review. 0 items remain.

Priority: unknown — motivation not written
Reviewed head: 7ad073f9
Owner decision: Required. See Explore Decisions.

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38297950722 |
| Local tests proof | N/A | remote PR — CI proof covers this |
| Review resolution | 6/6 | no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-12-modsecurity-leg pushed | `git` |
| OpenSpec | modsecurity-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190 | pr-host |
| CI | build 38297950722 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38297950722 | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38297950722 |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — added
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/modsecurity-leg/proposal.md) — added


## Deviations from the ask
- taken: absorb traefik-modsecurity (its public YAML keys). → dest naming family `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, `bouncerModsecFailMode` (same stems as `appsec*` / `lapi*` / `captcha*`). — `pkg/configuration/configuration.go` — honouring the source key names would add a second naming family next to the dest public surface.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-12-modsecurity-leg on branch 2026-10-12-modsecurity-leg targeting 2026-10-04-bouncer-refactor; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190; CI build 38297950722 succeeded https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/38297950722.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| How does a fourth leg bind (instance name, reclaim, subscribe) once designed? | bounded asked — changes existing `plugin.go` open/claim/Watch and `bouncer.New` (1 file + 1 constructor; three existing legs enumerated); Desired "A new ModSecurity leg alongside LAPI, AppSec, and captcha" | assumed — copy the dest pattern. Group `modsec`, alias `alias:modsec:<name>`, `modsecEnabled` owns, `bouncerEnabled` + non-empty `modsecInstanceName` subscribes, `Open` + `SetAlias` + `Watch` + `ReceiveModSec`. Exclusive publish and multi-leg rollback include this group (captcha-claim failure also `ClearPublisher` modsec). JSON stems `modsec*` (dest `appsec*`/`lapi*`/`captcha*`), not the source plugin's `modSecurityUrl` camelCase. | explore |


## Findings
None.

## Axis review
None.

## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 2 added / 6 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 7ad073f9099e636ef8881051e417e0fd4570bbbb | Card must match the branch you measured |

### Stored data model
None.
