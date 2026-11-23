## Motivation
A router can bounce a request against LAPI, AppSec and the ModSecurity sidecar, and each leg has a per-router `bouncer<Leg>FailureAction` for when its backend gives no answer. AppSec and ModSec also have an admission gate (`pkg/admission`) that stops calling a backend that keeps failing for a cooldown. LAPI in `live` / `none` mode had no such gate.

With LAPI down in `live` / `none`, every cache miss waited up to `lapiHttpTimeoutSeconds` (default 10) on each GET (the IP query plus one per mapped header scope) and only then got `bouncerLapiFailureAction`. The next miss paid the same wait, so an outage turned every uncached request into a multi-second stall with no bound.

On the WAF legs, a gate skip (`ErrGateSkip`: denied admission, or an unreadable body while backing off) always continued as if the WAF were not configured. That fail-open answer was hard-coded: an operator could not choose `ban` or `captcha` for it on any router. Copying the same rule to LAPI would have let banned IPs through for the whole LAPI outage.

The defaults did not match the intended stance. AppSec failed closed (`ban`) on the first failures, then opened for 30 seconds at a time. The ModSec gate was off (`modsecUnhealthyBackOffPeriodSecs: 0`), so a down sidecar was called on every request. An empty `bouncerAppsecFailureAction` resolved through the same `EffectiveFailureAction` as LAPI, so it meant `ban` even where the AppSec default was meant to change.

Priority: P2 — real operator and end-user pain during a LAPI or WAF outage (stalled requests, no per-router choice while a gate backs off), limited to outage windows and with failure actions as a partial workaround

## Implementation
Each gated leg gets a second per-router action, `bouncerLapiBackOffAction`, `bouncerAppsecBackOffAction` and `bouncerModsecBackOffAction` (`ban` / `passthrough` / `captcha`), validated by the same rule as the failure actions. The shared `EffectiveFailureAction` is replaced by per-leg resolvers, so an empty value means `ban` for LAPI and `passthrough` for AppSec and ModSec, for both the failure and the backoff action. `New()` sets the new defaults: AppSec failure action `passthrough`, AppSec and ModSec cooldown 10 seconds, and a new `lapiUnhealthyBackOffPeriodSecs` (default 10, `>= 0`, `0` = no gate).

`lapi.New` builds an admission gate (leg `lapi`, logs `crowdsec lapi backoff started` / `ended`) only in `live` and `none`, and `Close` closes it. `queryLiveDecisions` admits before every live GET, the IP query and each header-scope query alike. A denial sends no HTTP, caches nothing, and returns the sentinel `lapi.ErrGateSkip`. An admitted GET records health on the gate before parsing. To classify outcomes, `sendQuery` now returns an unexported `statusError` (status code plus the exact text it returned before) for non-2xx answers. Only the live path reads it: a transport error, a missing transport, a body read error, 429 and any 5xx are failures, while 2xx and every other 4xx (401/403 included) count as LAPI answering. Stream, alone and CAPI login ignore the type. The live/none cooldown joins the LAPI ownership key (0 in stream/alone), not the DecisionStore identity, so changing it reopens the Client and keeps the cache.

In the bouncer, one `applyBackOffAction` writer answers a gate skip on all three legs from that router's resolved action. `passthrough` continues, `captcha` serves the captcha gate unless a `bypassCaptcha` rule matched, and `ban` writes the ban page. The answer is labelled with a new `<leg>-backoff` header reason and reuses the leg's existing failure metrics origin. `applyLapiFailureAction` now takes its header reason as a parameter, so one origin can yield `lapi-failure`, `stream-unhealthy` or `lapi-backoff`. At startup, `bouncer.New` logs one WARN per subscribed leg whose backoff action ranks above its failure action (`passthrough` < `captcha` < `ban`). It skips LAPI when the router itself opens LAPI in stream/alone.

Real e2e adds a `lapi-flaky` nginx proxy in front of LAPI and a `live` route that is stopped and restarted to show trip, fast `ban:lapi-backoff` and recovery. `waf_backoff` adds a second router on the shared AppSec connection with `bouncerAppsecBackOffAction: ban`. Failure-action routes on permanently down backends pin their cooldown to 0.

## What this changes
**Operators.** Breaking defaults: `bouncerAppsecFailureAction` is now `passthrough` (was `ban`), `appsecUnhealthyBackOffPeriodSecs` is 10 (was 30), `modsecUnhealthyBackOffPeriodSecs` is 10 (was 0, off), and LAPI `live` / `none` owners get a 10-second gate (`lapiUnhealthyBackOffPeriodSecs`, `0` restores no gate). The new per-router `bouncerLapiBackOffAction` (default `ban`), `bouncerAppsecBackOffAction` and `bouncerModsecBackOffAction` (default `passthrough`) decide the answer while a gate backs off. A router with `bouncerModsecFailureAction: ban` now lets requests through without CRS while the newly default-on ModSec gate backs off unless it also sets `bouncerModsecBackOffAction: ban`. New signals to watch: `<kind>:lapi-backoff`, `<kind>:appsec-backoff` and `<kind>:modsec-backoff` verdict reasons, the `crowdsec lapi backoff started` / `ended` log lines, and the startup WARN `crowdsec bouncer backoff action stricter than failure action`.
**Admin users.** None.
**Developers.** `configuration.EffectiveFailureAction` is removed in favour of per-leg resolvers (`EffectiveLapiFailureAction`, `EffectiveAppsecFailureAction`, and `Effective<Leg>BackOffAction` for each leg), and `pkg/lapi` exports `ErrGateSkip`, `MsgBackoffStarted` / `MsgBackoffEnded` and `Client.GateForTest`.
**End users.** During an AppSec outage, visitors on routers that set no AppSec action are let through instead of banned. During a LAPI `live` / `none` outage, once the gate trips, visitors get the ban page at once instead of after the LAPI timeout.

## Merge readiness
In progress. 1 items remain.

Priority: P2 — real operator and end-user pain during a LAPI or WAF outage (stalled requests, no per-router choice while a gate backs off), limited to outage windows and with failure actions as a partial workaround
Reviewed head: b3cedb20
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
| Branch | 2026-11-23-backoff-action-per-leg pushed | `git` |
| OpenSpec | add-backoff-action-and-lapi-live-gate | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_lapi_admission-gate](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — added
- [core_plugin_lapi_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_lapi_query-round-trip](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_lapi_reclaim-key](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/openspec/changes/add-backoff-action-and-lapi-live-gate/proposal.md) — modified


## Deviations from the ask
- taken: add `lapiUnhealthyBackOffPeriodSecs` to the LAPI session identity (`pkg/lapi/session.go`), like AppSec does in `pkg/appsec/session.go`. → add it to the LAPI `ownership` payload (`OwnershipKey`), only in `live` / `none`; `streamSession` / `SessionHex` stay unchanged. — `pkg/lapi/identity.go` — AppSec's identity is its Client Open key; the LAPI equivalent is `ownership`, which reclaims the `lapi.Client` that holds the gate. `SessionHex` keys the DecisionStore, so a cooldown change there would drop the cache and the stream cursor.. Requester: confirmed.


## Follow-up issues
- [ ] [WAF failure-action captcha downgrade shows reason `LAPI`](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/knowledge/debt/2026-11-23-waf-failure-captcha-downgrade-reason.md) — an AppSec or ModSec failure-action captcha that downgrades to a ban shows ban-template reason `LAPI`, because `handleRemediationServeHTTP` hard-codes `ReasonLAPI`.


## How this fits together
Ticket 2026-11-23-backoff-action-per-leg on branch 2026-11-23-backoff-action-per-leg targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/236; CI not seen.

## Explore Decisions
None.

## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_standards.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_nitpicks.md) — 0 total, 0 pending, 0 completed
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_spec.md) — 1 total, 0 pending, 1 completed
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_security.md) — 1 total, 0 pending, 1 completed
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_performance.md) — 0 total, 0 pending, 0 completed
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_dead.md) — 0 total, 0 pending, 0 completed
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-backoff-action-per-leg/devstate/staging/2026/11/2026-11-23-backoff-action-per-leg/codereview_coverage.md) — 3 total, 0 pending, 3 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 1 added / 10 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | b3cedb20696ad6414298d89321372ebd894a73c5 | Card must match the branch you measured |

### Stored data model
None.
