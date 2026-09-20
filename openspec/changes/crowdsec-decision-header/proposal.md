## Why

Other Traefik middlewares cannot tell this bouncer to ban or captcha a client. After the trusted-IP skip, ServeHTTP always consults the stream cache or live LAPI. Operators who already decided “captcha this client” in a previous middleware have no way to reuse this plugin’s captcha gate and ban page.

## What Changes

- Add optional Config string `crowdsecDecisionHeader` (empty = off). When set, ServeHTTP reads that incoming header after the trusted-client skip.
- Exact trimmed values `b` (ban) and `c` (captcha) apply that remediation without `LookupRemediation` or `LiveLookup`. Map `b` to `BannedValue` (`t`) internally.
- Missing, empty, or any other token continues today’s lookup. Do not reject `New`.
- Reuse `handleRemediationServeHTTP`: a `c` header still honors the captcha gate, so a solved visitor reaches origin even while the header remains `c`.
- Forced drops count usage-metrics origin `plugin:forced_decision`.
- **Not BREAKING.** Empty default means DestBranch behavior.

## Capabilities

### New Capabilities

- `core_plugin_middleware_forced-decision`: Config-gated incoming header that forces ban or captcha without stream/live lookup, then reuses existing captcha-gate routing.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: Store/live lookup runs only when the forced-decision header does not hit.
- `core_plugin_lapi_usage-metrics`: Forced drops use origin `plugin:forced_decision`.

## Impact

- `pkg/configuration/configuration.go` (`CrowdsecDecisionHeader`)
- `pkg/bouncer/bouncer.go` (ServeHTTP after trusted skip)
- `pkg/lapi/client_metrics.go` (`OriginPluginForcedDecision`)
- Tests in `pkg/bouncer`, `pkg/configuration`, `pkg/lapi`
- README / Traefik examples for the new key
- Captcha gate cookie semantics unchanged (`core_plugin_middleware_captcha-gate`)
