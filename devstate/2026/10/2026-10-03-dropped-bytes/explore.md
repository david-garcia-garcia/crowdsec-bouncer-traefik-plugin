# Explore

## Concepts

Units this change would touch:

- **Inbound request** (`pkg/clientrequest/request.go`) — already embeds `*http.Request` and owns `IPType()`. Job: estimate size from `RequestURI`, `Host`, `Header`, and `ContentLength` without reading `Body`.
- **Drop recording** (`pkg/bouncer/bouncer.go` `recordDropped`) — today forwards origin, `ip_type`, and remediation only. Job: also pass that estimate on every remediating path.
- **Metrics window** (`pkg/lapi/client_metrics.go` `MetricsReporter`) — `usageMetricKey` already has a `unit` field; `IncDropped` hardcodes `unit: "request"`. Job: add a parallel `dropped` / `byte` window item and saturate those byte counters (including restore-on-failed-POST).
- **Live contract** (`openspec/specs/core_plugin_lapi_usage-metrics/spec.md`) — requires `dropped` / `request`. Job: propose folds an ADDED `dropped` / `byte` series beside it.
- **Proof** (`pkg/lapi/zzz_metrics_test.go`, `pkg/lapi/test_client.go` `TestDroppedCount`, `tests/e2e/real/usage_metrics.Tests.ps1`) — all keyed on unit `request`.

    *http.Request --> clientrequest.New (IPType, embed)
                           |
                           v
                Bouncer remediating path
          handleBanServeHTTP
          handleCaptchaKindServeHTTP (unsolved)
          handleAppsecResponseServeHTTP
                           |
                           v
                recordDropped(origin, ipType, remediation)
                           |
              +------------+------------+
              v                         v
     IncDropped unit=request    (proposed) estimate + dropped/byte
              |                         |
              +------------+------------+
                           v
              MetricsReporter.windowCounters
              addWindow / restoreMetricsWindow / POST
                           v
              LAPI POST /v1/usage-metrics
                           v
              cscli metrics show bouncers  (name + unit)

Call sites that matter (roots searched: worktree `pkg/**/*.go`, `tests/e2e/real/*.ps1`):

- Production `Client.IncDropped`: **1** (`recordDropped`).
- Production `recordDropped`: **3** (`handleBanServeHTTP`, unsolved captcha, AppSec envelope). Ban funnel into `handleBanServeHTTP`: **9** sites in `bouncer.go`.
- Test `IncDropped`: **5** in `pkg/lapi/zzz_metrics_test.go`.
- `TestDroppedCount` (hardcodes `unit: "request"`): **12** reads in `pkg/bouncer/*_test.go`.
- e2e `Get-CscliBouncerMetricValue -Name dropped -Unit request`: **2** cases in `usage_metrics.Tests.ps1`.

Reproduce: **reproduced — no dropped/byte item**.

- `MetricsReporter.IncDropped` always stores `unit: "request"` (`pkg/lapi/client_metrics.go`).
- `recordDropped` does not read request size or pass a byte delta.
- `addWindow` and `restoreMetricsWindow` use `+=` (wraps). `IncProcessed` uses `atomic.AddInt64` (wraps).
- Worktree search of `pkg/` and `tests/` found no usage-metrics unit `"byte"`.
- `go test ./pkg/lapi/ -count=1` in the worktree: **ok** (7.623s). Existing POST tests accept a request-only window.
- e2e only queries `-Unit "request"` for dropped.

Outside facts used:

- In-tree `knowledge/research/ext_crowdsec_lapi_usage-metrics/` — LAPI accepts any name/unit/labels; firewall sends `dropped` / `byte` with `origin` + `ip_type` (no `remediation`); `cscli` slices `origin` + `ip_type` and already knows unit `byte`.
- In-tree `knowledge/research/std_go_net-http_request-content-length/` — `ContentLength` field is the owner; Header may disagree; do not use `Request.Write`.
- In-tree `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` and `core_plugin_clientrequest_inbound-request.md`.
- Official Go 1.25.6 `net/http.Request`: incoming Host is promoted onto `Request.Host` and removed from `Header` (`golang/go@go1.25.6:src/net/http/request.go`). HTTP/2 `:authority` is that same Host field. Not written as a new research slug (requirement already names the lift).

## Decisions

- Chosen seam: keep `IncDropped` as the request counter. Add a byte increment into the same `windowCounters` map (unit distinguishes the item). `recordDropped` takes the inbound `req` and records both. Estimator lives on `clientrequest.Request` from the named fields only.
- Chosen labels for `dropped` / `byte`: `origin` + `ip_type`, omit `remediation` (firewall item shape). Request-series labels stay as they are.
- Chosen saturate: only byte window keys, including restore of those keys. A single capped estimate is `<= 50 MiB` and fits `int64`. Do not change request `+=` / `atomic.AddInt64` wrap.
- Chosen Host: `len(Request.Host)` only. Do not parse `:authority`, `X-Forwarded-Host`, or `Header["Host"]`.
- Chosen header bytes: `len(name)` once per Header map key plus `len(value)` for each value. No method/version/CRLF/colon-space.
- Chosen cap: 50 MiB (`50 * 1024 * 1024`) on the ContentLength part only, when `ContentLength >= 0`. `-1` adds nothing. Constant next to the estimator, not a Config knob.
- Rejected: `httputil.DumpRequest` / `Request.Write` (out of scope; would reconstruct a wire image and can touch Body).
- Rejected: reading Body when `ContentLength == -1`; `processed` / `byte`; unit `packet`; putting this plugin's bytes into the firewall bouncer's table.
- Rejected: changing the `IncDropped` signature (would migrate the 5 test call sites and `TestDroppedCount`).
- Rejected: saturating existing request counters.
- Rejected: reconstructing Host or `ip_type` (owners already exist).
- Live contract: `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` — fold ADDED `dropped` / `byte` beside the existing `dropped` / `request` SHALL. Propose owns the fold.

## Open questions

- Q: Which labels does the new `dropped` / `byte` item send?
  Rank: additive incidental — labels on an item this change creates; no In-scope or criterion line names those labels (Unknowns)
  Decision: assumed — `origin` + `ip_type` only, same values as the paired request item; omit `remediation` (firewall `dropped` / `byte` shape in `ext_crowdsec_lapi_usage-metrics`)
  By: explore

- Q: Is header contribution only `len(name)+len(value)`, or also wire separators?
  Rank: additive asked — new estimator this change creates; Out of scope forbids counting HTTP framing bytes (method, version, CRLF, colon-space) beyond the named fields
  Decision: resolved — `len(name)` once per Header key plus `len` of each value; no separators
  By: explore

- Q: How should HTTP/2 `:authority` interact with `len(Host)`?
  Rank: additive asked — new estimator this change creates; requirement names `len(Host)` because the server lifts Host out of the Header map
  Decision: assumed — use `Request.Host` only; Go already promotes `:authority` / Host there and deletes Host from Header (`golang/go@go1.25.6:src/net/http/request.go`). Do not parse `:authority`
  By: explore

- Q: Where does the estimator live, and do Yaegi constraints move that placement?
  Rank: additive asked — new helper this change creates; requirement says estimate from `*http.Request` and the clientrequest wrapper that embeds it
  Decision: assumed — method on `clientrequest.Request` (inbound-request owner). Yaegi constraint in-tree is select-case sharing on tickers, not a bar on a new method or file in this package
  By: explore

- Q: Does saturate apply only to byte window keys, or also to existing request counters?
  Rank: additive asked — new byte keys this change creates; requirement says the running byte counters (including failed-POST restore) must saturate
  Decision: assumed — saturate byte window add and restore only. Leave request `+=` and processed `atomic.AddInt64` wrapping
  By: explore

- Q: What is the blast radius of a second `dropped` series (`byte`) next to `request` in `cscli metrics show bouncers`?
  Rank: additive asked — new series this change creates; In-scope is an additional `dropped` / `byte` item, and Out of scope says not to put it in the firewall bouncer's own table (cscli already prints one table per bouncer)
  Decision: assumed — proceed. `cscli` already keys items by name and unit (`Get-CscliBouncerMetricValue` has `-Unit`; research `knownPlurals` includes `byte`). Existing e2e `-Unit request` cases stay valid
  By: explore

- Q: Who already owns Host and client address for this estimate?
  Rank: additive asked — estimate uses those fields; requirement names `len(Host)` and `ip_type` already comes from GetRemoteIP
  Decision: resolved — `pkg/ip.GetRemoteIP` plus `clientrequest.Request.IPType()` own client address / `ip_type`. `net/http` owns Host (`Request.Host`, promoted and removed from Header). Reuse those outputs. Do not reconstruct Host from `:authority`, Header, or AbsoluteURL. Do not parse `RemoteAddr`
  By: explore
