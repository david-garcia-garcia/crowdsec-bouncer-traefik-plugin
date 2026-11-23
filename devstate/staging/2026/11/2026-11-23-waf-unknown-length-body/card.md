## Motivation
Reported upstream as [maxlerebourg/crowdsec-bouncer-traefik-plugin#405](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/issues/405): "Silent 403 on HTTP/2 requests with an empty body (restic repo creation)". This PR supersedes [#204](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/204). #204 fixed the AppSec side only. It was built on a base older than the per-leg split (#219, #221), the shared `pkg/wafhop` package and the ModSec leg (#190), and it now conflicts with `master`.

Both WAF legs read the client body before they judge a request. `wafhop.IsBodyUnreadable` puts any HTTP/2 or HTTP/3 request that has a body but no `Content-Length` (`ContentLength < 0`) into an "unreadable" class, and nothing in that class is ever read. For POST, PUT and PATCH, each leg then hands the request to its failure action, which is meant for "the WAF gave no answer":

- **AppSec** (`bouncerAppsecFailureAction`, default `ban`): the request gets a 403 and AppSec is never queried. `restic init` against `rest-server` sends `POST <repo>/?create=true` over HTTP/2 with an empty body and no `Content-Length`, so it is silently banned. With `passthrough`, AppSec gets the headers only and the body reaches origin uninspected.
- **ModSec** (`bouncerModsecFailureAction`, default `passthrough`): the sidecar gets the headers only. With default settings, any client that leaves out `Content-Length` on HTTP/2 or HTTP/3 gets its body past CRS uninspected.
- **DELETE**, and any other method outside POST/PUT/PATCH, without `Content-Length` goes headers-only on both legs whatever the failure action. The same DELETE with the header has its body inspected.

`Content-Length` is optional in HTTP/2 and HTTP/3, so the client decides whether its body gets inspected. Because one failure action covers both "the WAF failed" and "the client sent no length", an operator cannot let restic through without also failing open when the WAF is down. HTTP/1.1 chunked bodies, which also have no length, are read today with no plugin deadline at all.

If nothing changes, ModSec's default setup has a body-inspection bypass that any client can trigger, AppSec's default setup blocks legitimate HTTP/2 clients that send no length, and the only workaround for one of these problems opens the other.

Priority: P1 — production is unsafe today: with ModSec's default failure action, any HTTP/2 or HTTP/3 client can skip body inspection by leaving out `Content-Length`.

## Implementation
Bodies of unknown length are no longer a separate class. `IsBodyUnreadable`, `IsMethodWithBody`, AppSec's `errUnreadableBody` and both drop branches are gone. Each leg reads every body it forwards through the one shared `wafhop.ReadBody` (AppSec: POST, PUT, PATCH, DELETE, truncated at `appsecBodyLimit`; ModSec: any method, 413 over `modsecBodyLimit`). A body that AppSec already read in full is reused by ModSec, with no second read and no second timer.

When `ContentLength < 0`, on any protocol (HTTP/1.1 chunked, HTTP/2, h2c, HTTP/3), `ReadBody` reads under a total deadline set per leg: `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, default 30, minimum 1. Each key lives on its leg's Client and in that leg's reclaim identity, because leg instances are shared by owner. The deadline works like this:

- A `time.AfterFunc` timer is armed only while this call actually reads from the client.
- When the timer fires, it calls `SetReadDeadline(time.Now())` on a per-request `*http.ResponseController` that the bouncer builds from `rw`. If there is no controller, or the call fails, it closes the body instead.
- After the read, `fired := !timer.Stop()` is checked before `IsClientGone`. On HTTP/1.1 the cut also cancels the request context, so checking for a disconnect first would wrongly treat the timeout as a client that left.
- The success path never sets a deadline, so Traefik's own `readTimeout` still bounds the rest of an oversize body.
- There is no goroutine, `select` or atomic type of the plugin's own, so the code runs under Yaegi.
- The parameter is the concrete controller, not an interface: under Yaegi v0.16.1, a nil check on an interpreted interface that holds the controller panics inside the timer goroutine (measured).

When the deadline fires, both legs return a new `wafhop.ErrBodyReadTimeout`. The bouncer answers it in one shared handler: HTTP 400, header `error:body-read-timeout`, no ban, no dropped metrics, no failure action, no gate record, and `next` is not called. It also writes a debounced (5 s) WARN per leg with `ip`, `method`, `host`, `path` (no query string) and `timeoutSeconds`, naming the leg's timeout key and its `bypassAppsec` / `bypassModsec` (or `bypass`) action. The answer is 400 rather than a ban because `master` already answers every "client body did not arrive whole" case (Traefik's `readTimeout` included) as 400 with no ban. The plugin's deadline is the same symptom on a shorter clock, and a ban would count a slow client as a WAF drop. 408 was rejected because clients retry it automatically. Each failure action now covers only a WAF that gave no verdict. `appsecBodyLimit <= 0` maps to 10 MiB through `configuration.EffectiveAppsecBodyLimit` (in `Prepare`, so the reclaim identity hashes 0, negative values and 10485760 the same, and in `New`). As a result, `ReadBody` no longer has a "no cap" mode.

Why not the alternatives (upstream PRs re-read on their current heads; both still open):

- **Upstream [#407](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/407):**
  - The wait is hardcoded (`time.Second`).
  - `appsecBodyLimit <= 0` still drops without reading.
  - `crowdsecAppsecUnreadableBodyBlock: false` and DELETE without `Content-Length` stay headers-only, so the client's signal still reduces inspection.
  - A read that times out runs in its own goroutine that nothing cancels. On Go's HTTP/2 server it ends when the stream closes; on an HTTP/1.1-shaped path it would hold the response. This plugin also avoids starting goroutines on the request path under Yaegi.
- **Upstream [#434](https://github.com/maxlerebourg/crowdsec-bouncer-traefik-plugin/pull/434):**
  - The client-controlled `Content-Type` picks the path (`application/grpc`, `application/grpc+*`, `application/connect+*`; a duplicated `Content-Type` counts as readable). With the flag set to `false`, a request that claims gRPC skips body inspection.
  - There is no plugin deadline: a stalled body fails only at Traefik's `readTimeout` (60 s by default).
  - gRPC unary calls are blocked by default.
  - HTTP/2/3 GET and DELETE without `Content-Length` stay headers-only.
- **Setting `crowdsecAppsecUnreadableBodyBlock: false`** (the workaround the #405 author verified): any client that leaves out `Content-Length` skips body inspection. That is the bypass this change removes.

Proof:

- Unit tests in `wafhop`, `appsec`, `modsecurity`, `configuration` and `bouncer` cover the restic shape reaching origin on both legs, a 400 under every failure action, and the WARN debounce.
- A Yaegi v0.16.1 test runs the deadline path.
- The mock AppSec e2e, on Traefik v3.7.19, measured a 400 at 2.0 s for stalled HTTP/1.1 chunked and HTTP/2 bodies with a 2 s timeout. #204 had recorded that an HTTP/1.1 read could not be cut on v3.7.11; that limitation does not reproduce here.
- The real ModSec e2e over h2c lets the restic shape through, blocks an XSS body sent without a length, and answers a stalled body with 400 `error:body-read-timeout`.
- HTTP/3 was not measured; the docs say "expected".

## What this changes
**Operators.** Breaking: `appsecBodyLimit` 0 or negative now means 10 MiB (0 used to mean no cap, negative was a validation error); bodies without `Content-Length` (HTTP/1.1 chunked, HTTP/2, HTTP/3) are now read, capped and inspected on both legs, so ModSec inspects bodies it used to pass headers-only; each leg's new `appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds` (default 30, minimum 1) answers a body that does not arrive in time with HTTP 400 `error:body-read-timeout` and a WARN, whatever the failure action says, so routes that stream request bodies (gRPC client/bidi, Connect streaming, slow uploads) need a `bouncerActionRules` `bypassAppsec` / `bypassModsec` (or `bypass`) rule or a higher timeout; and the failure actions no longer cover the client's body.
**Admin users.** None.
**Developers.** `appsec.Client.Query` gains a `*http.ResponseController` parameter, `modsecurity.Client.Inspect` takes one instead of `failureAction`, `wafhop.ReadBody` takes the controller and a timeout and requires `limit >= 1`, `wafhop.IsBodyUnreadable` / `IsMethodWithBody` are removed, and the new `ErrBodyReadTimeout` (in `wafhop`, aliased in `appsec`) must be handled apart from `ErrClientBodyRead`.
**End users.** A client that sends a body without `Content-Length`, such as `restic init` over HTTP/2, now reaches the application after inspection instead of getting a silent 403, and a request body that never ends within the timeout gets HTTP 400.

## Merge readiness
In progress. 1 items remain.

Priority: P1 — production is unsafe today: with ModSec's default failure action, any HTTP/2 or HTTP/3 client can skip body inspection by leaving out `Content-Length`.
Reviewed head: 4916b386
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
| Branch | 2026-11-23-waf-unknown-length-body pushed | `git` |
| OpenSpec | waf-inspect-unknown-length-body | `openspec/` |
| Pull request | https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/237 | pr-host |
| CI | not seen | caller omitted CI snapshot |
| Local tests | passed | handoff.yaml localTests |
| PR comments | no comments | devstate/comments.md |

## Specs
Worktree:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified
- [core_plugin_wafhop_shared-request](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/changes/archive/2026-11-23-waf-inspect-unknown-length-body/proposal.md) — modified

Completed:
- [core_plugin_appsec_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_appsec_client/spec.md) — modified
- [core_plugin_appsec_failure-action](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_appsec_failure-action/spec.md) — modified
- [core_plugin_middleware_bouncer](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_middleware_bouncer/spec.md) — modified
- [core_plugin_middleware_config-validation](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_middleware_config-validation/spec.md) — modified
- [core_plugin_modsecurity_client](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_modsecurity_client/spec.md) — modified
- [core_plugin_modsecurity_inspect](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_modsecurity_inspect/spec.md) — modified
- [core_plugin_wafhop_shared-request](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/openspec/specs/core_plugin_wafhop_shared-request/spec.md) — modified


## Deviations from the ask
- taken: a total read deadline on bodies of unknown length, implemented once in `pkg/wafhop` for both legs, that blocks independently of the failure action (decisions 1 and 2); no criterion names a signature change. → `appsec.Client.Query(req, pol, dl)` gains a third parameter and `modsecurity.Client.Inspect(req, dl)` replaces its `failureAction` parameter (used only by the removed drop branch). `dl` is a narrow `wafhop.ReadDeadliner` the bouncer builds from `rw` with `http.NewResponseController`. Call sites migrated here: `Query` 1 production + 69 test, `Inspect` 1 production + 5 test (explore.md, Call sites). — `pkg/bouncer (sole owner of rw); pkg/wafhop/body.go (ReadBody, owner of the read and the deadline)` — the response writer is the only handle that sets a read deadline on HTTP/1.1 (`Body.Close` cannot cut it, #204 measurement); the bouncer owns it and the shared read owns the cut. Rank `bounded incidental` (explore.md, open question on how the control reaches `pkg/wafhop`).. Requester: not asked.


## Follow-up issues
- [ ] [AppSec call is not canceled when the client leaves](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/knowledge/debt/2026-11-23-appsec-call-ignores-inbound-cancel.md) — the AppSec listener request does not carry the inbound context, so a client that leaves keeps the call open until `appsecHttpTimeoutSeconds` (pre-existing; found by the 180 s `Test_appsecQuery_hopCancelDoesNotTripGate`).


## How this fits together
Ticket 2026-11-23-waf-unknown-length-body on branch 2026-11-23-waf-unknown-length-body targeting master; PR https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/pull/237; CI not seen.

## Explore Decisions
| Question | Rank | Decision | By |
| --- | --- | --- | --- |
| One deadline key per leg or one shared key; name, default, validation, and does it enter each leg's reclaim identity? | additive asked — two new public keys and two identity fields; decision 1 "Whether there is one key per leg (`appsecBodyReadTimeoutSeconds` / `modsecBodyReadTimeoutSeconds`, consistent with per-leg settings and shared leg instances) or one shared key: explore decides and records why" | assumed — one key per leg: `appsecBodyReadTimeoutSeconds` (Go `AppsecBodyReadTimeoutSeconds`) and `modsecBodyReadTimeoutSeconds` (Go `ModsecBodyReadTimeoutSeconds`), `int64`, `omitempty`, default `30` each, in `requiredInt1` next to the `*HTTPTimeoutSeconds` siblings (`< 1` → `<Name>: cannot be less than 1`); no `0 = disabled` mode (it would reopen the hang decision 1 closes). Why per leg: leg instances are shared by owner (`appsecInstanceName` / `modsecInstanceName`, owner Open + alias), and a router may run AppSec owned by one middleware and ModSec owned by another; each leg's knobs live on its own Client and reclaim key (`pkg/appsec/session.go:18-31`, `pkg/modsecurity/session.go:20-26`), so a shared key would have no owner. Each key joins its leg's identity (a change Opens a new Client, spec "reclaimed by listener/sidecar identity"). Default 30 s: below Traefik's default `readTimeout` of 60 s (`traefik/traefik@v3.7.19:pkg/config/static/static_config.go:51`), so with Traefik defaults the plugin's logged block fires first; enough for 10 MiB on roughly 2.8 Mbit/s. Inside each package the stored field drops the leg prefix (`bodyReadTimeout`). | explore |


## Findings
None.

## Axis review
[Standards](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_standards.md) — 3 total, 0 pending, 1 completed, 2 skipped
[Nitpicks](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_nitpicks.md) — 7 total, 0 pending, 2 completed, 5 skipped
[Spec](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_spec.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Scope](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_scope.md) — 0 total, 0 pending, 0 completed
[Security](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_security.md) — 3 total, 0 pending, 1 completed, 2 skipped
[Performance](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_performance.md) — 2 total, 0 pending, 0 completed, 2 skipped
[Dead](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_dead.md) — 2 total, 0 pending, 1 completed, 1 skipped
[Test coverage](https://github.com/david-garcia-garcia/crowdsec-bouncer-traefik-plugin/blob/2026-11-23-waf-unknown-length-body/devstate/staging/2026/11/2026-11-23-waf-unknown-length-body/codereview_coverage.md) — 1 total, 0 pending, 1 completed


## Agent review details

### Review metrics
| Metric | Value | Why it matters |
| --- | --- | --- |
| Specs in this PR | 0 added / 14 modified | Same list as ## Specs |
| Open reviewer comments walked | 0 FIX / 0 ANSWER / 0 open | Unanswered review is merge risk |
| Reviewed head | 4916b38676eacf611791323c3c765feba774d5ea | Card must match the branch you measured |

### Stored data model
None.
