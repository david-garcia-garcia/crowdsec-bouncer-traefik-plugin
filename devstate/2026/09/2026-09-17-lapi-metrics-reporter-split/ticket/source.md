# Split MetricsReporter off Client

IssueKey: 2026-09-17-lapi-metrics-reporter-split
issueHost: local
issueRef: none
prHost: github
repoSlug: crowdsec-bouncer-traefik-plugin
destBranch: master

This ticket takes the follow-up recorded in `knowledge/debt/2026-09-17-metrics-reporter-split.md`.

Today the usage-metrics counters and the metrics POST ticker live directly on `lapi.Client` (`pkg/lapi/client_metrics.go`: `handleMetricsTicker`, `drainMetrics`, `IncProcessed`, `IncDropped`, `addWindow`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, `restoreMetricsWindow`, plus their fields on the `Client` struct). Extract a `MetricsReporter` type that owns that counter window and the reporting ticker, so metrics stop riding the LAPI client’s identity.

`master` (currently `e6cc9ab`) just merged PR #62, which extracted the LAPI HTTP+auth transport into its own type stored on the client in an `atomic.Value` and made it replaceable by the last `New` via `AdoptTransport(cfg)`. Read `pkg/lapi/client_http.go`, `pkg/lapi/client.go` and `openspec/changes/archive/2026-09-17-lapi-transport-router-policy/design.md` before designing. The debt states the constraint that matters: the reporter must POST through that replaceable transport and MUST NOT re-introduce a write-once `*http.Client` field of its own, because that is exactly the coupling #62 removed.

Hard constraints, because this plugin runs under Traefik’s Yaegi interpreter:
- Do NOT use `atomic.Pointer[T]`. Yaegi v0.16 cannot handle a generic instantiation from another package as a struct field. Use `atomic.Value` with a comment saying why, as `pkg/lapi/client.go` does.
- Do NOT convert existing write-once scalar fields on `Client` into mutable ones. Their readers do not take the mutex.
- Keep the metrics reporter on the same reclaim lifetime as the cursor. Do not give it a second ticker or a second reclaim entry in this ticket.

Scope fence — two sibling tickets are running in parallel:
Stay inside `pkg/lapi/client_metrics.go`, the metrics fields of `pkg/lapi/client.go`, `pkg/lapi/zzz_metrics_test.go`, and the OpenSpec leaf `core_plugin_lapi_usage-metrics`.

Do NOT touch:
- the reclaim keying in `pkg/lapi/session.go` (`SessionKey`, `settingsFrom`, `streamSettings`, `CachePrefix`, `reclaimSessionKey`) or `pkg/lapi/identity.go`
- `openspec/specs/core_plugin_middleware_instance-reclaim/`
- `pkg/appsec/`, `pkg/captcha/` and the `core_plugin_appsec_*` leaves
- `pkg/cache/` internals and `pkg/reclaim/` internals

Touching `client.go` is expected, but keep it to the metrics fields and their construction; do not reshape the transport or the session code. If design genuinely requires editing a fenced-off file, stop and report it as `blocked`.

When implement lands the work, close the debt: delete `knowledge/debt/2026-09-17-metrics-reporter-split.md` and record the closure on this run’s `issues.md` and delivery card.

Debt file current content (IssueKey on the debt file is the PREVIOUS ticket that noted it; THIS ticket’s IssueKey is `2026-09-17-lapi-metrics-reporter-split`):

```
# Split MetricsReporter off Client
IssueKey: 2026-09-17-lapi-transport-router-policy
Size: large
Action: note
## Why this follow-up
Usage-metrics counters and the POST ticker still live on `lapi.Client`. A MetricsReporter type would own that window without riding the HTTP transport.
## Why it was not taken
Out of scope. Ticket forbids a MetricsReporter split in this apply.
## Risks
Metrics keep using the replaceable transport; a reporter split later must not re-introduce a write-once HTTP client field.
```
