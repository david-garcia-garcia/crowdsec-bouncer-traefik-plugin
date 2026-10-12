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
Reviewed head: e14db187
Owner decision: Required. See Explore Decisions.

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
| Branch | 2026-10-12-modsecurity-leg pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: absorb traefik-modsecurity (its public YAML keys). → dest naming family `modsecEnabled`, `modsecUrl`, `modsecInstanceName`, `bouncerModsecFailMode` (same stems as `appsec*` / `lapi*` / `captcha*`). — `pkg/configuration/configuration.go` — honouring the source key names would add a second naming family next to the dest public surface.. Requester: not asked.


## Follow-up issues
None.

## How this fits together
Ticket 2026-10-12-modsecurity-leg on branch 2026-10-12-modsecurity-leg targeting 2026-10-04-bouncer-refactor; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190; CI not seen.

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
| Specs in this PR | none | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | e14db187e66e7b4d4e268b904f654b6b66fa68a8 | Card must match the branch you measured |

### Stored data model
None.
