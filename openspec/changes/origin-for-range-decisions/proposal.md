## Why

On master, Range-only drops omit usage-metrics `origin` because stream writes a letter into `range-index` and membership returns that letter. Ip and header-scope already store `t`/`c` plus U+001F plus `MetricsOrigin`. Operators cannot slice Range-only bans in `cscli metrics show bouncers`.

## What Changes

- Stream Range upserts store `RemediationWithOrigin(letter, MetricsOrigin(origin, scenario))` on the existing `range-index` blob.
- `MembershipFromIndex` / `Remediation` return the winning CIDR’s stored string (ban over captcha). Bare `cidr=t` still matches.
- Range-only `LookupCachedRemediation` origin matches Ip/header. Redis stays one `range-index` key.
- Specs: Range-only origin required when stored; blob MAY carry the same suffix as Ip/header.
- Usage packets that say range-index stays letter-only are updated.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_lapi_usage-metrics`: Range-only drops SHALL send `origin` when the winning Range CIDR stored it. Letter-only blob lines MAY still omit origin.
- `core_plugin_decisions_scopes`: `range-index` lines MAY carry the same origin suffix as Ip/header. Membership returns the winning CIDR’s stored string. Bare `cidr=t` still remediates.

## Impact

- `pkg/crowdsecconnection/connection_stream.go` Range upsert value
- `pkg/decisionscope` membership payload resolution; lookup comment
- Unit tests for blob suffix round-trip, Range-only lookup origin, letter-only still bans
- `knowledge/devdocs/core_plugin_lapi_usage-metrics.md` and `core_plugin_decisionscope.md`
