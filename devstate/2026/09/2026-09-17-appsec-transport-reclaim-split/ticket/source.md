# Split AppSec reclaim/transport the way LAPI just did

IssueHost: local
IssueRef: none
IssueKey: 2026-09-17-appsec-transport-reclaim-split

This ticket takes the follow-up recorded in `knowledge/debt/2026-09-17-appsec-captcha-split.md`. Read that file as the ticket source.

`master` (currently `e6cc9ab`) just merged PR #62, which did this for the LAPI client: it moved per-router policy (failure action, Redis fail-closed, live-cache TTL) down onto the `Bouncer`, extracted the HTTP+auth transport into its own type stored on the client in an `atomic.Value`, added an `AdoptTransport(cfg)` call after reclaim so the last `New` wins the transport, and removed the per-router policy fields plus the TLS and HTTP-timeout fields from the settings hash that keys instance reclaim. Read `openspec/changes/archive/2026-09-17-lapi-transport-router-policy/` (proposal, design, tasks, spec deltas), `knowledge/devdocs/core_plugin_lapi_connection.md`, `pkg/lapi/client_http.go` and `pkg/lapi/session.go` to understand that shape before you design anything.

The debt names the residual risk: AppSec still keys its own reclaim incarnation the way LAPI used to, so an AppSec TLS or timeout reload still splits the AppSec reclaim key and throws away a perfectly good client. Apply the same treatment to AppSec: get AppSec TLS, AppSec HTTP timeout, and any per-router AppSec policy out of the AppSec reclaim key, and make the AppSec transport adoptable by the last `New` instead of soldered to the reclaimed object. Confirm the exact current AppSec keying in `pkg/appsec/` during explore before you commit to a design — do not assume it mirrors LAPI field for field.

Honor the same hard constraints the LAPI change had, because this plugin runs under Traefik's Yaegi interpreter:
- Do NOT use `atomic.Pointer[T]`. Yaegi v0.16 cannot handle a generic instantiation from another package as a struct field. Use `atomic.Value` with a comment saying why, exactly as `pkg/lapi/client.go` does.
- Do NOT convert existing write-once scalar fields into mutable ones. Their readers do not take the mutex.

Scope fence — two sibling tickets are running in parallel right now.
Stay inside `pkg/appsec/`, `pkg/captcha/`, the AppSec-related OpenSpec leaves (`core_plugin_appsec_client`, `core_plugin_appsec_failure-action`, `core_plugin_appsec_bot-detection`, `core_plugin_middleware_captcha-gate`), and whatever minimal wiring in `pkg/bouncer/` you genuinely need.

Do NOT touch, in this ticket:
- `pkg/lapi/` (any file), especially `session.go`, `client.go`, `client_http.go`
- `openspec/specs/core_plugin_middleware_instance-reclaim/` — a sibling ticket is renaming that leaf
- `openspec/specs/core_plugin_lapi_usage-metrics/` and `pkg/lapi/client_metrics.go` — a sibling ticket owns those
- `pkg/reclaim/` internals

If your design genuinely requires editing one of those, stop and report it as `blocked` with the reason instead of editing it. Run `skill:sbs-dev-workflow:Sync` before implement and before pullrequest, because `master` may move under you when a sibling PR merges; merge `origin/master` and re-verify rather than rebasing a pushed branch.

When implement lands the work, close the debt per `skill:sbs-dev-workflow:Issues`: delete `knowledge/debt/2026-09-17-appsec-captcha-split.md` and record the closure on your own run's `issues.md` and delivery card. Do NOT edit or stage the previous run's bus folder `devstate/2026/09/2026-09-17-lapi-transport-router-policy/`.
