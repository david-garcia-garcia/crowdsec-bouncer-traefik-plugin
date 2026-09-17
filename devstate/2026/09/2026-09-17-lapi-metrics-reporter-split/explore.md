# Explore
IssueKey: 2026-09-17-lapi-metrics-reporter-split

## Concepts

This is a parked extract, not a runtime failure. DestBranch `lapi.Client` still owns the usage-metrics window and the POST ticker (`pkg/lapi/client_metrics.go`, metrics fields on `pkg/lapi/client.go`). After #62, LAPI HTTP+auth is a replaceable `atomic.Value` `transport`; `reportMetrics` already POSTs through `c.crowdsecQuery`, which loads `currentTransport()` on every call (`pkg/lapi/client_http.go`). The debt (`knowledge/debt/2026-09-17-metrics-reporter-split.md`) is to give that window a `MetricsReporter` owner without putting a write-once `*http.Client` on the reporter.

Traefik calls `New` once per router-handler build (`ext_traefik_plugins_yaegi-constructor`). This process already binds that constructor `ctx` through in-tree `pkg/reclaim` (`std_go_reclaim`, `core_plugin_middleware`). There is no `core_plugin_reclaim` packet. The reclaim value is `*lapi.Client`. Last holder `Sleep`s (async `drainMetrics`), Open during grace `Wake`s the same `startTicker` helper, grace `Close`s (sync `drainMetrics` before idle HTTP). Do not add `sync.Once`, a package global, or a second `reclaim.Open` for metrics.

```
Traefik New ctx
    └─ reclaim.Open (one key, one Client)
           ├─ stream ticker          startTicker in client.go
           ├─ metrics ticker         same helper, same Sleep/Wake/Close
           ├─ transport              atomic.Value (not atomic.Pointer[T])
           └─ metrics window         today: fields on Client
                                     intended: *MetricsReporter field
                                               POST via crowdsecQuery method value
```

Bouncer call sites stay on `Client`: `IncProcessed` / `IncDropped` (`pkg/bouncer/bouncer.go`). Stream/alone gauge updates stay on `Client`: `rememberActiveDecision` / `forgetActiveDecision` (`pkg/lapi/client_stream.go`, `pkg/lapi/client_decisions.go`). Those files are outside this ticket’s fence. Thin `Client` wrappers are the only way to move the window without editing them.

Request-path `ip_type` is already classified. Owner is `pkg/ip.GetRemoteIP` folded into `clientRequest.ipType`. `IncProcessed` / `IncDropped` consume that string. They must not parse `RemoteAddr`. Gauge `ip_type` is a different fact: `ip.FamilyOfHostOrCIDR(decisionValue)` on the stored decision, not the visitor.

`metricsInterval` is a write-once first-wins reclaim setting (`session.go` `streamSettings`, `identity.go`). Those files are fenced. The scalar stays on `Client` for ticker start/stop and the `drainMetrics` no-op when `<= 0`. Do not make it mutable. Do not move the hash.

`attachTestTransport` lives in `pkg/lapi/zzz_session_test.go` (outside the test fence). Metrics tests keep using it. Existing `pkg/lapi` metrics tests passed in this explore (`go test ./pkg/lapi/ -run TestMetrics|TestIncProcessed|TestReportMetrics|TestSleepDrains|TestCloseDrains` → ok).

No active OpenSpec change (`openspec list --json` → empty). Fold into `core_plugin_lapi_usage-metrics`. Do not touch `core_plugin_middleware_instance-reclaim`.

## Decisions

- Extract `MetricsReporter` in `pkg/lapi/client_metrics.go` (same usage-metrics job; ticket fence forbids a new product file). `Client` holds one `*MetricsReporter` for the cursor’s reclaim lifetime. No second ticker. No second reclaim table entry. Hooks stay `client.Sleep` / `client.Wake` / `client.Close`.
- Reporter owns the window: `windowCounters`, processed atomics, `activeDecisions` / `activeDecisionSlots`, `metricsMu`, `reportMu`, `lastMetricsPush`, and the POST/restore path. `Client` keeps `metricsStop`, write-once `metricsInterval`, and the `startTicker` wiring in `New` / `Sleep` / `Wake` / `Close`.
- POST through the replaceable transport without editing `client_http.go`: inject an unexported query func on the reporter, bound in `Client.New` (and in-fence test helpers) to the `crowdsecQuery` method value. That method already loads `currentTransport()` each call. Snapshot write-once URL pieces (`scheme` / `host` / `path`) and envelope scalars (`pluginVersion`, `startedAt`, `crowdsecMode`) onto the reporter at construct. Do not store `*http.Client`. Do not use `atomic.Pointer[T]`.
- `IncProcessed`, `IncDropped`, `rememberActiveDecision`, `forgetActiveDecision`, `reportMetrics`, `drainMetrics`, and `handleMetricsTicker` stay `Client` methods as thin forwards (bouncer / stream / decisions / existing tests are outside or depend on that surface).
- Tests in `zzz_metrics_test.go` keep `attachTestTransport` and construct the reporter beside the Client literal (or via a helper in that file). They may read reporter fields through the `Client` field. Do not edit `zzz_session_test.go`.
- Yaegi: any new atomic field follows `client.go` `transport` — `atomic.Value` plus a why-comment. This split should not need a new atomic field; the query func is write-once at construct.
- Propose FindSpecHost: fold into `core_plugin_lapi_usage-metrics`. Do not invent a reporter leaf. Do not edit fenced specs.
- Usage `core_plugin_lapi_usage-metrics.md` still tells implementers to call `Client.IncProcessed` / `IncDropped`. Explore writes no Language and no usage edit. Implement / devdocsimpact update the ticker sentence after the apply.
- Research: existing `ext_crowdsec_lapi_usage-metrics`, `ext_traefik_plugins_yaegi-constructor`, `ext_traefik-middleware-utilities_packages` answer LAPI POST / Yaegi / reclaim facts. No new research folder.
- When implement lands, delete `knowledge/debt/2026-09-17-metrics-reporter-split.md` and close the matching `issues.md` row.

## Open questions

- Q: Who already owns identity (visitor address, decision-value family, LAPI HTTP+auth, reclaim lifetime)?
  Decision: assumed — visitor address / request-path `ip_type` is `pkg/ip.GetRemoteIP` on `clientRequest` (reuse `req.ipType`; do not parse `RemoteAddr`). Gauge `ip_type` is `ip.FamilyOfHostOrCIDR` on the decision value. LAPI HTTP+auth is `Client.transport` (`atomic.Value`); reporter POSTs via `crowdsecQuery`, not a new owner. Reclaim lifetime is `*lapi.Client` on the existing table entry; reporter is a field, not a second key.
  By: explore

- Q: How does the reporter reach `crowdsecQuery` / `currentTransport()` without editing `pkg/lapi/client_http.go` and without a write-once `*http.Client`?
  Decision: assumed — unexported query func on `MetricsReporter`, bound to `c.crowdsecQuery` at construct. Snapshot write-once URL and envelope scalars then. Do not reshape transport. Do not store HTTP.
  By: explore

- Q: Do `IncProcessed` / `IncDropped` stay on `Client`?
  Decision: assumed — yes, thin forwards. Bouncer call sites are outside the file fence. Same for `rememberActiveDecision` / `forgetActiveDecision` (stream and decisions files).
  By: explore

- Q: Does `metricsInterval` move onto the reporter?
  Decision: assumed — no. It stays a write-once `Client` scalar (reclaim hash lives in fenced `session.go` / `identity.go`). Client uses it to start/stop the existing ticker and to skip drain when `<= 0`.
  By: explore

- Q: New file for `MetricsReporter` (One job, one owner) vs stay in `client_metrics.go`?
  Decision: assumed — stay in `client_metrics.go`. The type is the same usage-metrics job. The ticket fence forbids a new product file.
  By: explore

- Q: Would this design require a fenced file (`session.go`, `identity.go`, `client_http.go`, `pkg/reclaim/`, `pkg/appsec/`, instance-reclaim spec)?
  Decision: assumed — no. Wrappers + injected `crowdsecQuery` + Client-held reporter keep the fence. If propose later needs a fenced file, that row becomes `blocked`.
  By: explore
