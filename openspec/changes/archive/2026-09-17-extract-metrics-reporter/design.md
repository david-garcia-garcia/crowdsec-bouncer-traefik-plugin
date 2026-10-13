## Context

See `proposal.md` Why. Dest `master` still stores the usage-metrics window and POST path on `lapi.Client` (`pkg/lapi/client_metrics.go`, fields on `pkg/lapi/client.go`). #62 already POSTs through `crowdsecQuery` → `currentTransport()` (`atomic.Value`, not `atomic.Pointer[T]`). Reclaim value is `*lapi.Client`; last holder `Sleep`s (async drain), Open during grace `Wake`s the same `startTicker` helper, grace `Close`s (sync drain before idle HTTP). Bouncer and stream/decisions call `Client` methods; those files are outside this ticket’s fence.

FindSpecHost:

```
verdicts:
  - { deltaId: metrics-reporter-owns-window, fold|new: fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_lapi_connection, core_plugin_lapi_stream-lease] }
```

Search: family `core_plugin_lapi`; existing leaves `usage-metrics` (window/POST/envelope), `connection` (replaceable transport), `stream-lease` (ticker helper), `failure-action`. No in-flight change folder. Small adjustment (three ADDED requirements) to the leaf that already owns dropped/processed/gauge/envelope — not a new product capability (no new skill, store, or root/domain pair). `usage-metrics` names the unit. Do not invent a reporter leaf. Do not fold into `connection` (transport reshape is fenced) or `instance-reclaim` (reclaim keying is fenced).

## Goals / Non-Goals

**Goals:**

- Window and POST/restore live on `MetricsReporter`; `Client` holds one pointer for the cursor’s lifetime.
- POST through the replaceable transport without a reporter-owned `*http.Client`.
- Same ticker and reclaim entry as today.

**Non-Goals:**

- Editing `client_http.go`, `session.go`, `identity.go`, `pkg/reclaim/`, `pkg/appsec/`, or `core_plugin_middleware_instance-reclaim`.
- A second metrics ticker, a second `reclaim.Open`, or `sync.Once`.
- Making remaining write-once Client scalars mutable.
- `atomic.Pointer[T]`.
- Moving `IncProcessed` / `IncDropped` call sites off `Client`.
- Updating usage Language in this change folder (implement / devdocsimpact).
- Deleting the debt file before implement.

## Decisions

1. **Stay in `client_metrics.go`.** Same usage-metrics job. Ticket fence forbids a new product file. Alternative: a new file for One job, one owner — rejected; the type is not a second job.
2. **Inject an unexported query func, bound to `c.crowdsecQuery` at construct.** That method already loads `currentTransport()` each call. Do not edit `client_http.go`. Alternative: store `*http.Client` on the reporter — rejected (#62). Alternative: `atomic.Pointer` to transport — rejected (Yaegi v0.16).
3. **Snapshot write-once URL pieces (`scheme` / `host` / `path`) and envelope scalars (`pluginVersion`, `startedAt`, `crowdsecMode`) onto the reporter at construct.** POST must not read mutable Client identity. `startedAt` moves with the envelope (owner of `utc_startup_timestamp`). Tests that stamped `Client.startedAt` stamp the reporter instead.
4. **Ticker stays on `Client`.** `metricsStop`, write-once `metricsInterval`, and `startTicker` wiring in `New` / `Sleep` / `Wake` / `Close` stay. Alternative: reporter owns a second ticker — rejected (same reclaim lifetime). Alternative: move `metricsInterval` onto the reporter — rejected; the scalar is a first-wins reclaim setting whose hash lives in fenced `session.go` / `identity.go`.
5. **Thin `Client` wrappers.** Bouncer, stream, decisions, and existing tests stay on `Client`. Alternative: move the methods and edit those files — rejected (fence).
6. **Tests stay on `attachTestTransport` and construct the reporter beside the Client literal** (or a helper in `zzz_metrics_test.go`). Do not edit `zzz_session_test.go`.
7. **No new atomic field.** The query func is write-once at construct. If a later hunk needs an atomic, follow `Client.transport`: `atomic.Value` plus a why-comment.
8. **Fold, do not invent a reporter leaf.** FindSpecHost fold into `core_plugin_lapi_usage-metrics`.
9. **Implement deletes `knowledge/debt/2026-09-17-metrics-reporter-split.md`** and closes the matching `issues.md` row.

## Risks / Trade-offs

- [Client literals in `zzz_metrics_test.go` still set window fields on `Client`] → Helper in that file constructs `MetricsReporter` and binds the query func after `attachTestTransport`. Fail loud on a nil reporter rather than hide a missed construct.
- [Query func closes over `Client` while reporter also snapshots URL pieces] → Snapshot is for the metrics URL and envelope only. Auth and `*http.Client` stay on the replaceable transport via `crowdsecQuery`.
- [Duplicate `startedAt` on Client and reporter] → Move the envelope stamp onto the reporter. Do not leave a unused Client field.
- [Nil reporter on a test Client that only needed HTTP] → Metrics tests always construct it. Production `New` always constructs it.

## Migration Plan

No operator JSON/YAML key change. Rollback is revert. Catalog users pick up the type split with the next plugin release; in-process Clients from an old snapshot die on grace.
