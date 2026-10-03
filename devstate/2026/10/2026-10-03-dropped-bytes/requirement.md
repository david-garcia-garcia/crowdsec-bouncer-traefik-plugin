# Requirement
IssueKey: 2026-10-03-dropped-bytes

Send dropped bytes to CrowdSec LAPI usage-metrics the way the firewall bouncer does: an additional `dropped` item whose unit is `byte`, estimated from the HTTP request this plugin already has, without reading the body.

Estimate the request size from fields on `*http.Request` (and the clientrequest wrapper that embeds it):

- `len(RequestURI)` for the request-target as sent
- `len(Host)` because the server lifts Host out of the Header map
- length of each header name and each header value already in `Header`
- the declared `ContentLength` when it is `>= 0`

Do not read `Body`. Do not call `httputil.DumpRequest` or `Request.Write`. Do not send unit `packet`.

Cap content-length: if the request reports `ContentLength` greater than 50 mebibytes (50 * 1024 * 1024), count 50 mebibytes for that part. The human wrote "50Mb"; use 50 MiB (52428800 bytes).

Storage must not overflow over time. The running byte counters (the usage-metrics window that is summed until the next successful POST, including a failed POST that restores the window) must saturate instead of wrapping. A single request's capped estimate must also fit the counter type.

Keep the existing `dropped` / `processed` items whose unit is `request`. This adds the byte series. It does not replace request counts.

Out of scope for the ask (do not take them as requirements): reading the body when ContentLength is -1; estimating packets; sending `processed` with unit `byte`; putting the estimate in the firewall bouncer's own table (cscli already prints one table per bouncer).

## Current (code)

- `pkg/lapi/client_metrics.go` — `IncDropped` adds a `dropped` item with unit `request` (origin, ip_type, remediation). `IncProcessed` adds `processed` with unit `request` (ip_type). No item with unit `byte`. Window map values are `int64`; `addWindow` and `restoreMetricsWindow` use `+=`, which wraps. Processed counts use `atomic.AddInt64`, which wraps.
- `pkg/bouncer/bouncer.go` — `recordDropped` forwards origin, ip_type, and remediation only. Ban (`handleBanServeHTTP`), captcha (unsolved gate), and AppSec envelope (`handleAppsecResponseServeHTTP`) call it. They do not pass a byte estimate.
- `pkg/clientrequest/request.go` — `Request` embeds `*http.Request`, so `RequestURI`, `Host`, `Header`, and `ContentLength` are already on the wrapper. No size estimate. Dest files: `request.go`, `zzz_request_test.go`.
- `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` — live contract requires `dropped` and `processed` with unit `request`. It does not require a `dropped` / `byte` series.
- Content-length cap of 50 MiB (52428800) — not found
- Saturating byte window counters — not found
- `httputil.DumpRequest` / `Request.Write` on the drop path — not found

## Affected

- `pkg/lapi/client_metrics.go` — window keys, POST items, restore-on-failed-POST
- `pkg/bouncer/bouncer.go` — drop recording
- `pkg/clientrequest/request.go` — estimate from the embedded `*http.Request`
- `openspec/specs/core_plugin_lapi_usage-metrics/spec.md` — live contract
- `pkg/lapi/zzz_metrics_test.go` — usage-metrics item tests
- `tests/e2e/real/usage_metrics.Tests.ps1` — e2e usage-metrics

## Out of scope

From the ask (do not take):

- Reading `Body` when `ContentLength` is -1
- Estimating or sending unit `packet`
- Sending `processed` with unit `byte`
- Putting the estimate in the firewall bouncer's own table (cscli already prints one table per bouncer)
- Calling `httputil.DumpRequest` or `Request.Write`
- Replacing the existing `dropped` / `processed` items whose unit is `request`

Inferred extras (do not take):

- Changing `active_decisions`
- Reading the body to refine the estimate
- Counting HTTP framing bytes (method, version, CRLF, colon-space) beyond the named fields
- A public config knob for the 50 MiB cap

## Unknowns

- Labels on the `dropped` / `byte` item. Firewall sends `origin` + `ip_type` and no `remediation`. This plugin's `dropped` / `request` items may also send `remediation`. The ask does not name labels.
- Whether header contribution is only `len(name)+len(value)` per map entry, or also separators the wire would have used
- How HTTP/2 `:authority` vs the lifted `Host` field should interact; the ask names `len(Host)`
- Where the estimator lives (`clientrequest` vs bouncer vs reporter) and Yaegi constraints on that placement
- Whether saturate applies only to byte window keys (as written) or also to `request` counters
- Blast radius of adding a second `dropped` series next to `request` in `cscli metrics show bouncers`

## Tensions

- Informal "50Mb" vs 50 MiB (52428800). The caller already chose 50 MiB. Not a code conflict.
- Firewall also sends `dropped` / `packet` and `processed` / `byte`. The ask keeps those out of scope. Not a product add.
- Live spec `core_plugin_lapi_usage-metrics` requires `dropped` unit `request` only. The ask adds a `byte` series beside it; propose owns the spec fold.
