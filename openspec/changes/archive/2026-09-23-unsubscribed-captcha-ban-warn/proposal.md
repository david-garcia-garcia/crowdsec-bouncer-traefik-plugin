## Why

A bouncing router that never subscribed to captcha can still receive a captcha kind (LAPI, forced header `c`, or a captcha failure-action that already reached remediation). Dest already bans that request. The operator is not told this router never subscribed, so the degrade looks like a normal ban.

## What Changes

- When `handleRemediationServeHTTP` sees captcha kind and `subscribeCaptcha` is false, emit WARN `crowdsec bouncer captcha unsubscribed` with `leg=captcha` and `instanceName` (empty when unsubscribed), then the existing ban.
- WARN on every remediating request that hits that branch. Do not add a `Once` field.
- Do not emit `ip`. Client address stays `pkg/ip.GetRemoteIP` on `clientRequest`.
- Do not WARN when subscribed (including subscribed-unpublished and `!Valid`). Startup-block 503 plus `crowdsec bouncer backend missing` stays as-is.
- No new public config keys. Failure-action `captcha` without an instance name stays illegal at `ValidateParams`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: unsubscribed captcha kind WARNs then bans; subscribed-unpublished stay on the existing ban / startup-block paths.

## Impact

- `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP` (one WARN, gated on captcha kind and `!subscribeCaptcha`).
- Tests in `pkg/bouncer` that drive captcha kind on bounce-only / unsubscribed routers and the subscribed-unpublished sibling (assert this WARN is absent).
- `plugin.go` subscribe gate is read-only; no new knob.
- Live catalog fold only. Neighbors stay as-is: `core_plugin_middleware_captcha-routing`, `core_plugin_middleware_forced-decision`, `core_plugin_lapi_failure-action`, `core_plugin_appsec_failure-action`.
- Usage packets stay for implement / `opd-devdocsimpact` (Language already names Subscribe / Captcha Client / Bouncer).
