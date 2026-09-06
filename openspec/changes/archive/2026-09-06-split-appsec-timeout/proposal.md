## Why

A single `HTTPTimeoutSeconds` (default 10s) is the `http.Client.Timeout` for both slow LAPI stream pulls and per-request AppSec queries. When AppSec is unreachable, every request waits that full timeout before `crowdsecAppsecFailureAction`. Operators who lengthen LAPI timeout make AppSec outages hang the site.

## What Changes

- Add public `CrowdsecAppsecTimeoutMilliseconds` (`crowdsecAppsecTimeoutMilliseconds`). Zero / omit inherits `HTTPTimeoutSeconds`. A positive value is that many milliseconds. Negative is invalid.
- Wire AppSec `http.Client.Timeout` (and AppSec reclaim identity) to the effective AppSec duration. LAPI and captcha siteverify stay on `HTTPTimeoutSeconds`.
- Document the knob next to other `CrowdsecAppsec*` keys. Recommend `200` when the operator wants CrowdSec spec-style short AppSec hang plus `passthrough`.
- Unit tests: inherit vs override, hanging AppSec + passthrough returns allow under the LAPI timeout, identity keys match on equal effective duration.
- Not **BREAKING**. Omit keeps today’s shared-timeout behavior.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_appsec_client`: AppSec HTTP timeout is `CrowdsecAppsecTimeoutMilliseconds` when set, else `HTTPTimeoutSeconds`. Reclaim identity hashes that effective duration, not raw LAPI seconds.

## Impact

- `pkg/configuration/configuration.go` (field, validation, `EffectiveAppsecTimeout`)
- `pkg/appsec/client.go`, `pkg/appsec/session.go`
- README AppSec / `HTTPTimeoutSeconds` docs
- Tests under `pkg/configuration/` and `pkg/appsec/`
- Usage packet `knowledge/devdocs/core_plugin_appsec.md` (timeout line)
