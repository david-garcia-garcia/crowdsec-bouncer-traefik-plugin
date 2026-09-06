## Why

On `master`, this bouncer POSTs one `dropped` count to CrowdSec LAPI `v1/usage-metrics` with `labels.type=traefik_plugin`. `cscli metrics show bouncers` never reads that label; it slices on `origin` and `ip_type`. Official bouncers send `dropped`, `processed`, and `active_decisions`. Operators cannot see this plugin the way they see nginx/firewall remediations.

## What Changes

- POST `dropped` / `processed` / `active_decisions` items with official labels (`origin`, `ip_type`, and `remediation` when the drop is ban vs captcha). Drop `labels.type=traefik_plugin`.
- Map list decisions to `origin=lists:<scenario>`. Do not send a `scenario` label.
- Classify `ip_type` from `pkg/ip.GetRemoteIP` (ipv4/ipv6). Do not parse `RemoteAddr` again.
- Persist decision origin on cache values so stream/live hits can still label `dropped`. Matching keys stay the same; the remediation letter is unchanged.
- Stamp `utc_startup_timestamp` once at connection start.

## Capabilities

### New Capabilities

- `core_plugin_lapi_usage-metrics`: CrowdsecConnection POSTs LAPI usage-metrics the way official remediation components do (`dropped` / `processed` / `active_decisions`, labels `origin` / `ip_type` / `remediation`).

### Modified Capabilities

- `core_plugin_decisions_scopes`: Cache remediation strings MAY carry an origin suffix. Matching still uses the ban/captcha letter. Lookup keys (IP, header, range-index) do not change.

## Impact

- `pkg/crowdsecconnection` metrics ticker, stream/live cache writes, `IncBlocked` replaced by labeled increments
- `pkg/bouncer` ServeHTTP processed/dropped accounting
- `pkg/cache` remediation-letter helpers
- `pkg/decisionscope` IsActiveRemediation / PreferRemediation / lookup on suffixed values
- `pkg/ip` family of an already-resolved address
- Unit tests for payload and origin rewrite; mock LAPI still accepts the POST
