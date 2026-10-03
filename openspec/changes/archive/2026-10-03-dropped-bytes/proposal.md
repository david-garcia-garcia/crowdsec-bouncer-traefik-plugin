## Why

This plugin already POSTs `dropped` / `request` to CrowdSec LAPI usage-metrics. Official firewall bouncers also send a `dropped` item whose unit is `byte`. Operators comparing `cscli metrics show bouncers` tables cannot see how much request weight this plugin remediates.

## What Changes

- Each remediating drop also increments a `dropped` item with unit `byte` in the same usage-metrics window, beside the existing `dropped` / `request` item. Request counts stay.
- Estimate those bytes from fields already on the inbound `clientrequest.Request` (`RequestURI`, `Host`, `Header`, declared `ContentLength`). Do not read `Body`. Do not call `httputil.DumpRequest` or `Request.Write`.
- Cap the `ContentLength` contribution at 50 MiB (`50 * 1024 * 1024`) when `ContentLength >= 0`. `-1` adds nothing. The cap is a constant next to the estimator, not a Config knob.
- Byte-window keys saturate on add and on failed-POST restore. Request `+=` and processed `atomic.AddInt64` stay wrapping.
- Labels on the byte item are `origin` + `ip_type` only (same values as the paired request item). Omit `remediation`.
- Fold the live contract `core_plugin_lapi_usage-metrics` with an ADDED `dropped` / `byte` series. Usage packet `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` updates when implement lands.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_usage-metrics`: ADDED `dropped` / `byte` series beside `dropped` / `request`; estimate from inbound request fields with a 50 MiB ContentLength cap; saturate those byte window keys.

## Impact

- `pkg/clientrequest/request.go` (estimator on `Request`; dest files `request.go`, `zzz_request_test.go`)
- `pkg/bouncer/bouncer.go` (`recordDropped` takes `req` and records both series)
- `pkg/lapi/client_metrics.go` (byte window item, saturate on add/restore)
- `pkg/lapi/zzz_metrics_test.go`, `pkg/bouncer` `TestDroppedCount` stay keyed on unit `request`
- `tests/e2e/real/usage_metrics.Tests.ps1` (existing `-Unit request` stays; add a byte-series case)
- OpenSpec fold only `core_plugin_lapi_usage-metrics`. Do not add a clientrequest or bouncer spec folder (estimator and `recordDropped` are how that contract is met).
- Usage packet when implement lands. Do not silent-rename it.
- No **BREAKING** public JSON/YAML keys
- Out of scope: reading `Body` when `ContentLength` is `-1`; unit `packet`; `processed` / `byte`; putting this plugin's bytes into the firewall bouncer's table; changing `active_decisions`; HTTP framing bytes; a public cap knob; saturating request counters; changing the `IncDropped` signature
