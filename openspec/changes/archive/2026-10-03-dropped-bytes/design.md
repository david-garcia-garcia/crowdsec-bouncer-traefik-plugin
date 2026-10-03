## Context

See `proposal.md` — Why. Dest `MetricsReporter.IncDropped` always stores `unit: "request"` (`pkg/lapi/client_metrics.go`). `addWindow` and `restoreMetricsWindow` use wrapping `+=`. `recordDropped` forwards origin, `ip_type`, and remediation only (`pkg/bouncer/bouncer.go`); three remediating call sites already have `req`. `clientrequest.Request` embeds `*http.Request` and owns `IPType()`; it has no size estimate. Identity-owner: inbound request owns the estimate; `pkg/ip.GetRemoteIP` plus `IPType()` own `ip_type`; `net/http` owns Host (`devstate/explore.md`).

FindSpecHost (propose, before folder write):

```
verdicts:
  - { deltaId: dropped-byte-series, fold, spec-id: core_plugin_lapi_usage-metrics, confidence: high, candidates: [core_plugin_lapi_usage-metrics, core_plugin_clientrequest_inbound-request, core_plugin_middleware_bouncer] }
```

Small adjustment: two ADDED requirements on the existing usage-metrics leaf. Estimator and `recordDropped` are how that contract is met. Do not add a clientrequest or bouncer spec folder. Do not silent-rename `core_plugin_lapi_usage-metrics`.

## Goals / Non-Goals

**Goals:**

- Method on `clientrequest.Request` estimates size from the named live fields.
- `recordDropped` takes `req` and records request + byte series.
- Same `windowCounters` map; `unit` distinguishes the item. Saturate byte keys on add and restore.

**Non-Goals:**

- Changing `IncDropped` signature; saturating request / processed counters; snapshotting size in `New`; a Config cap; reading Body; unit `packet`; `processed` / `byte`.

## Decisions

1. **Estimator on `clientrequest.Request`.** `EstimatedSize() int64` sums `len(RequestURI)`, `len(Host)`, `len(name)` once per Header map key, `len(value)` for each value, and `ContentLength` when `>= 0` capped at `50 * 1024 * 1024`. Nil embed or `ContentLength == -1` adds nothing for the missing part. Constant lives next to the method. Alternative: helper in `pkg/lapi` or `pkg/bouncer` — rejected (inbound-request owner; that package must not import those). Alternative: snapshot in `New` — rejected (these fields stay on the live embed; drop time is the observation).

2. **Keep `IncDropped`. Add `IncDroppedBytes(origin, ipType string, n int64)`.** Client thin-forward matches `IncDropped`. Reporter stores `usageMetricKey{name: "dropped", unit: "byte", origin, ipType}` with empty remediation so POST omits that label. Alternative: grow `IncDropped` with a byte argument — rejected (migrates the five test call sites and `TestDroppedCount`). Alternative: `recordDropped` reaching `addWindow` — rejected (`Inc*` stay Client methods).

3. **`recordDropped(req, origin, remediation)`.** `ip_type` comes from `req.IPType()`. Calls `IncDropped` then `IncDroppedBytes` with `req.EstimatedSize()`. The three remediating sites (ban, unsolved captcha, AppSec envelope) pass `req`. Alternative: keep a parallel `ipType` argument — rejected (owner already on `req`).

4. **Saturate only when `key.unit == "byte"`.** Shared add used by `addWindow` and restore: if `cur > MaxInt64 - delta` (delta `> 0`) store `MaxInt64`. Zero delta does not create a byte key (same skip-zero as processed). Request keys and processed atomics stay wrapping `+=` / `atomic.AddInt64`. Alternative: saturate every window key — rejected (explore: byte keys only).

5. **Usage packet after apply.** Dest usage still documents request-only `IncDropped`. Propose does not rewrite `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` (consume: dest matches until implement). Implement updates How to use / snippet / gotchas when the byte series lands. Do not silent-rename it.

## Risks / Trade-offs

- **[Risk] Header map iteration misses hop-deleted Host** → Mitigation: add `len(Host)` separately; Go already lifted Host and removed it from Header.
- **[Risk] A later mutation of the live `*http.Request` changes the estimate** → Mitigation: estimate at `recordDropped`, the same moment the request series increments.
- **[Trade-off] Estimate is not a wire image** → Accepted; out of scope forbids DumpRequest / framing bytes / Body.
- **[Trade-off] `cscli` shows a second `dropped` row keyed by unit `byte`** → Accepted; research already pluralizes `byte` and e2e already passes `-Unit`.

## Migration Plan

Single deploy. No public config. Existing `dropped` / `request` items unchanged. Rollback is revert.

## Open Questions

None. Proceed policies live on `devstate/explore.md`.
