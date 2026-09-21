## Why

`pkg/crowdsecconnection/connection.go` is 842 lines packing construct/close, stream, live lookup, AppSec, LAPI/CAPI HTTP, and metrics. Later connection work keeps landing in that god file. The package already split reclaim identity and decision helpers; finish the same physical split.

## What Changes

- Split remaining jobs out of `connection.go` into same-package files: `connection_appsec.go`, `connection_stream.go`, `connection_live.go`, `connection_http.go`, `connection_metrics.go`.
- Keep `CrowdsecConnection`, `Prepare`, `New`, `Close`, accessors, and range membership in `connection.go`.
- Same exported API. No new packages. No behavior change.

No **BREAKING** public JSON config keys. No signature changes.

## Capabilities

### New Capabilities

- `core_plugin_connection_source-files`: CrowdsecConnection jobs live in named same-package files; the type and exported API stay on `package crowdsecconnection`.

### Modified Capabilities

None.

## Impact

- `pkg/crowdsecconnection/connection.go` shrinks; five new files in that package.
- Tests in `pkg/crowdsecconnection/` stay in the same package (no import changes).
- Callers in `plugin.go` and `pkg/bouncer` unchanged.
- Usage packets that cite only `connection.go` get path notes at devdocs impact.
