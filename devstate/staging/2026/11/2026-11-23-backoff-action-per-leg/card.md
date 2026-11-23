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
In progress. 1 items remain.

Priority: unknown — motivation not written
Reviewed head: 0071cc74
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
| Branch | 2026-11-23-backoff-action-per-leg pushed | `git` |
| OpenSpec | none | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | none | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
None.

## Deviations from the ask
- taken: add `lapiUnhealthyBackOffPeriodSecs` to the LAPI session identity (`pkg/lapi/session.go`), like AppSec does in `pkg/appsec/session.go`. → add it to the LAPI `ownership` payload (`OwnershipKey`), only in `live` / `none`; `streamSession` / `SessionHex` stay unchanged. — `pkg/lapi/identity.go` — AppSec's identity is its Client Open key; the LAPI equivalent is `ownership`, which reclaims the `lapi.Client` that holds the gate. `SessionHex` keys the DecisionStore, so a cooldown change there would drop the cache and the stream cursor.. Requester: not asked.


## Follow-up issues
- [ ] [WAF failure-action captcha downgrade shows reason `LAPI`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/knowledge/debt/2026-11-23-waf-failure-captcha-downgrade-reason.md) — an AppSec or ModSec failure-action captcha that downgrades to a ban shows ban-template reason `LAPI`, because `handleRemediationServeHTTP` hard-codes `ReasonLAPI`.


## How this fits together
Ticket 2026-11-23-backoff-action-per-leg on branch 2026-11-23-backoff-action-per-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| Can the real e2e stack stop LAPI for a live-backoff test without breaking other suites? | additive asked — new compose service, new route, new cases; existing suites keep their routes; requirement section 7 asks for the LAPI live backoff case when the stack allows it | assumed — yes, without stopping `crowdsec`. Add compose service `lapi-flaky` (`nginx:alpine`, container `lapi-flaky-test`, `config/lapi-flaky.conf` with `resolver 127.0.0.11` and a `set $lapi http://crowdsec:8080` `proxy_pass`, the `appsec-flaky.conf` shape). Add one `live` middleware/router `/lapi-cycle` in a file-provider YAML with `lapiHost: lapi-flaky:80`, its own key `BOUNCER_KEY_LAPI_BACKOFF` (next free `c51a1c70…1c`, registered in the crowdsec env list), `lapiUnhealthyBackOffPeriodSecs: 10`, `lapiHttpTimeoutSeconds: 2`, `lapiMetricsUpdateIntervalSeconds: 0`, `reclaimGraceSeconds: 2`, JSON log, verdict header. Cycle: one fresh `X-Forwarded-For` per request (live caches a clean answer for `lapiDefaultDecisionSeconds`); stop `lapi-flaky-test`, 5 × `ban:lapi-failure`, then fast `ban:lapi-backoff` (assert elapsed well under the 2 s timeout), exactly one `crowdsec lapi backoff started`; start it, wait for 200, exactly one `crowdsec lapi backoff ended`; `AfterAll` starts the container. Place it in `waf_backoff.Tests.ps1` (domain `modsec`, which already owns stop/start cycles) or a new `lapi_backoff.Tests.ps1` registered in `PesterDomains.ps1` `lapi`; propose picks. Non-default WAF BackOffAction: a second router subscribing to the `/appsec-cycle` AppSec instance by name with `bouncerAppsecBackOffAction: ban`, proving the shared gate and the per-router action in the same outage. | explore |


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
| Reviewed head | 0071cc74c7a47832942b718ae63db2f6e1f5b190 | Card must match the branch you measured |

### Stored data model
None.
