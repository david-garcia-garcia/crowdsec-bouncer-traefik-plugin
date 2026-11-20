## Motivation
Two operator problems, one PR.

**CRS inspection needs a second plugin.** The bouncer has three legs today: LAPI, AppSec and captcha. Operators who want OWASP CRS through ModSecurity must also load `david-garcia-garcia/traefik-modsecurity` as a separate Traefik middleware. That plugin repeats what this one already has (trusted IPs, bypass rules, remediation header, instance sharing) with its own config keys. The goal is for this plugin to become a single edge WAF instead of a set of pieces to assemble.

**A down AppSec takes ingress down.** Every failed AppSec call (unreachable, 5xx, unreadable body) applies `bouncerAppsecFailureAction`, whose default is `ban`. Nothing remembers that AppSec is down, so during an outage every request is banned until someone switches to `passthrough` by hand.

Priority: P2 — real operator pain with a workaround and limited blast radius

## Implementation
**ModSec leg.** A fourth leg, `modsec`, built like the captcha leg. `modsecEnabled` owns a client and publishes it under `modsecInstanceName`; other routers subscribe with `bouncerEnabled` plus that name. The client copies each request to `modsecUrl` (an inspect-only CRS sidecar) and reads the status:
- **2xx**: allow, continue to the origin.
- **3xx / 4xx**: block. The sidecar's response goes to the visitor; redirects are not followed.
- **5xx or no answer**: the WAF failed. Per-router `bouncerModsecFailMode` decides: `open` (default) continues, `close` returns an empty 502.

Order in `ServeHTTP`: LAPI → AppSec → ModSec → origin. Trusted clients skip all three. In `bouncerActionRules`, the new token `bypassModsec` skips only ModSec, and `bypass` now skips all three. Before calling the sidecar: methods that must not carry a body (default GET, HEAD, DELETE, OPTIONS, TRACE, CONNECT) get 400 if they do, and bodies over `modsecBodyLimit` get 413 (default 8 MiB; `0` also means 8 MiB, there is no unlimited value). WebSocket handshakes are inspected like any GET.

**Backoff gate (AppSec and ModSec).** New `pkg/admission` wraps the utilities `backendbackoff.Gate`. After enough failures the gate stops calling the backend for a cooldown, then lets one probe through; a successful probe reopens traffic. It logs two lines per outage, never one per request: WARN `crowdsec <leg> backoff started` and INFO `crowdsec <leg> backoff ended`.
- **AppSec:** on by default (`appsecUnhealthyBackOffPeriodSecs: 30`). While it skips, requests continue without AppSec and **without** `bouncerAppsecFailureAction` (then ModSec, if subscribed). Failures before the trip still apply that action (`ban` by default). This is the intended resilience: an AppSec outage stops banning traffic once the gate trips.
- **ModSec:** off by default (`modsecUnhealthyBackOffPeriodSecs: 0`); a skip follows `bouncerModsecFailMode`.

Trip rule, both legs: a failure budget (`*UnhealthyFailureThreshold`, default 5). Each failure spends one unit and each success earns back part of one. With the defaults the gate trips after 5 failures in a row, or when failures stay above about 30% of requests.

**Docs and tests.** README documents the ModSec leg and drops the separate `traefik-modsecurity` listing. Real e2e adds Pester domain `modsec` with an inspect-only Apache CRS sidecar: allow, CRS block, 413, GET with body, fail open/close, backoff skip, WebSocket and `bypassModsec`.

## What this changes
**Operators.** New keys `modsecEnabled`, `modsecUrl`, `modsecInstanceName` (owner) and `bouncerModsecFailMode` (per router), plus `modsec*` body and backoff knobs. The source plugin's `modSecurityUrl` is not read. **Behaviour change:** AppSec backoff is on by default; once it trips, requests pass without AppSec instead of being banned. Set `appsecUnhealthyBackOffPeriodSecs: 0` to keep the old per-request `bouncerAppsecFailureAction`. `bypass` rules now also skip ModSec. Watch for the `backoff started` / `backoff ended` log lines.
**Admin users.** None.
**Developers.** `bouncer.New` takes a fourth subscribe flag; reclaim group `modsec`; action token `bypassModsec` and `ActionMatch.SkipModsec`; `appsec.ErrGateSkip` means AppSec was not called and FailureAction must not run; remediation header value `ban:modsec`; shared `pkg/admission` for backend backoff gates.
**End users.** During an AppSec outage, visitors stop being banned once the gate trips. When ModSec is enabled, a CRS block shows the sidecar's 403 page.

## Merge readiness
Ready for review. 0 items remain.

Priority: P2 — real operator pain with a workaround and limited blast radius
Reviewed head: 85d81cd7
Owner decision: Taken. Skipping AppSec without FailureAction after a trip is the intended behaviour (resilience to AppSec outages).

## Review scores
| Measure | Result | What it means |
| --- | --- | --- |
| Overall readiness | 6/6 | Ready |
| CI proof | 6/6 | 8/8 checks succeeded on 85d81cd7 (build + lint + Yaegi https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778892, e2e incl. Pester modsec https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778922) |
| Local tests proof | 6/6 | go unit tests, golangci-lint and the real-stack Pester `modsec` domain (11/11) passed on 85d81cd7 |
| Review resolution | 6/6 | 6 review findings resolved, no open PR comments |

## Verification
| Check | Result | Evidence |
| --- | --- | --- |
| Branch | 2026-10-12-modsecurity-leg pushed | `git` |
| OpenSpec | modsecurity-leg | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190 | pr-host |
| CI | 8/8 checks succeeded on 85d81cd7 (build + lint + Yaegi https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778892, e2e incl. Pester modsec https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778922) | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778892 · https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778922 |
| Local tests | passed | `go test ./...`, `golangci-lint run`, Pester `modsec.Tests.ps1` against Docker (11 passed, 0 failed) |
| PR comments | no comments | devstate/comments.md |

## Specs
Change deltas (archived with this PR):
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_middleware_instance-slots/spec.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_modsecurity_client/spec.md) — added
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/changes/archive/2026-10-12-modsecurity-leg/specs/core_plugin_modsecurity_inspect/spec.md) — added

Resulting specs:
- [build_e2e_pester_crowdsec-stack](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/build_e2e_pester_crowdsec-stack/spec.md) — modified
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_middleware_instance-slots](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_middleware_instance-slots/spec.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_modsecurity_client/spec.md) — added
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-10-12-modsecurity-leg/openspec/specs/core_plugin_modsecurity_inspect/spec.md) — added


## Deviations from the ask
- taken: config keys use this plugin's naming (`modsecEnabled`, `modsecUrl`, `modsecInstanceName`, `bouncerModsecFailMode`), not the source plugin's `modSecurityUrl`. — `pkg/configuration/configuration.go` — keeps one naming family next to `appsec*` / `lapi*` / `captcha*`. Requester: not asked.
- taken: the source plugin's `bypassRules` list becomes the `bypassModsec` token in `bouncerActionRules`. — `pkg/httprule/action.go` — one rule list for every skip instead of a second one. Requester: not asked.


## Follow-up issues
None filed. Suggested before a fifth leg (for example a rate limiter):
- Extract a common leg abstraction. Each leg is added by copying the same `switch` in `plugin.go` and the `xxxBound` / `xxxReceived` / `ReceiveXxx` set in `Bouncer`.
- Read the request body once and share it. With AppSec and ModSec both on, each holds its own copy in memory.

## How this fits together
Ticket 2026-10-12-modsecurity-leg on branch 2026-10-12-modsecurity-leg targeting 2026-10-04-bouncer-refactor; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/190; CI 8/8 checks succeeded on 85d81cd7 (build + lint + Yaegi https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778892, e2e incl. Pester modsec https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/actions/runs/43618778922).

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| How does a fourth leg bind (instance name, reclaim, subscribe)? | bounded asked — changes `plugin.go` open/claim/Watch and `bouncer.New` | Copy the existing leg pattern. Group `modsec`, alias `alias:modsec:<name>`. `modsecEnabled` owns; `bouncerEnabled` + non-empty `modsecInstanceName` subscribes (`Open` + `SetAlias` + `Watch` + `ReceiveModSec`). If a later claim fails, every leg already published by that middleware is rolled back, ModSec included. | explore |
| After the AppSec gate trips, apply FailureAction or skip? | owner | Skip: requests continue without AppSec and without FailureAction. Resilience to AppSec outages is the goal. | owner |


## Findings
Review on 44108bfb, all resolved in 4a38eed8, b785144a and 85d81cd7:
- Gate skips were not logged for AppSec and were logged once per request for ModSec → `pkg/admission` logs only `backoff started` and `backoff ended`.
- `modsecBodyLimit: 0` meant unlimited, an unbounded in-memory body per request → `0` now means 8 MiB, as in the source plugin.
- The e2e backoff case returned 200 with or without the gate → it now asserts one sidecar hit for four requests and a single `backoff started` line.
- README called the trip threshold "consecutive failures" → now described as a failure budget.
- The source plugin's WebSocket e2e family was not ported → ported (echo through the leg, CRS payload on the handshake blocked, lone `Upgrade` header still inspected).
- AppSec skipping FailureAction after a trip → kept on purpose (owner decision above).

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
| Specs in this PR | 2 added / 6 modified (each listed twice above: change delta and resulting spec) | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 85d81cd7 | Card must match the branch you measured |

### Stored data model
None.
