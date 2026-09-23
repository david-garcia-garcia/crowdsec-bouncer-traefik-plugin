## Why

Captcha is still built per bouncing router from that router’s `bouncerCaptcha*` copy. Operators cannot name one captcha client, share it across routers, or bounce before the owner exists. LAPI and AppSec already do that through reclaim aliases; captcha is the missing third leg.

## What Changes

- Add own-axis keys `captchaEnabled` and `captchaInstanceName`. Bounce stays `bouncerEnabled`. Failure actions stay `bouncerLapiFailureAction` / `bouncerAppsecFailureAction`.
- Owner middleware Opens a captcha client, publishes reclaim group `captcha` (`alias:captcha:<name>`). Subscribers Watch only. Reuse the existing reclaim table; do not add a second slot implementation.
- Empty `captchaInstanceName` fills to the Traefik name only when `captchaEnabled` is true. Default `captchaEnabled` is false (no implicit own from a set provider).
- Owner-style checks (provider, keys, gate secret, loadable template) run only when `captchaEnabled`. Subscriber leftover `bouncerCaptcha*` is ignored.
- `captcha` failure action is legal only when this router has a captcha instance name (after owner fill).
- `bouncer.New` does not construct a local captcha client. Startup block on → 503 for an unpublished subscribed captcha name. Startup block off → continue; a captcha verdict with no published client is a ban.
- Remediation header stays on the Bouncer. Lift `remediationCustomHeader` off the shared `captcha.Client` so a subscriber does not inherit the owner’s header.
- In-repo examples and e2e that today treat provider-set as own set `captchaEnabled: true`.
- **BREAKING**: YAML that only sets `bouncerCaptchaProvider` no longer owns or serves captcha. Operators must set `captchaEnabled: true` (empty name fills). `captcha` failure action without `captchaInstanceName` fails `ValidateParams`.

## Capabilities

### New Capabilities

None.

### Modified Capabilities

- `core_plugin_middleware_instance-slots`: third reclaim group `captcha` on the existing alias table; owner Open + SetAlias; empty-name fill when owned.
- `core_plugin_middleware_bouncer`: third `atomic.Value` binding; no local captcha construct; startup-block includes captcha; header lifted off the shared client; missing published client + captcha verdict is a ban.
- `core_plugin_middleware_config-validation`: new `captcha*` own-axis keys; owner checks gated on `captchaEnabled`; failure-action `captcha` gated on instance name; public prefix list includes `captcha`.
- `core_plugin_lapi_failure-action`: `captcha` requires a captcha instance name, not a local provider.
- `core_plugin_appsec_failure-action`: same gate; AppSec-only captcha action uses the subscribed published client.
- `core_plugin_middleware_captcha-gate`: gate secret required when `captchaEnabled`, not when a leftover provider is set.
- `build_e2e_pester_crowdsec-stack`: compose / labels / file-provider YAML include `captchaEnabled` / `captchaInstanceName`.

## Impact

- `plugin.go` — third `legCaptcha` in `openOwned` / `claimOwned` / `Watch`; `captcha.Prepare`; subscribe flag.
- `pkg/configuration` — `CaptchaEnabled`, `CaptchaInstanceName`; validation gates.
- `pkg/captcha` — `Prepare`, reclaim Open / ownership key; header off `Client`; siteverify timeout on the owner client.
- `pkg/bouncer` — third binding, `ReceiveCaptcha`, startup-block, no `Client.New` from subscriber keys.
- README, `examples/captcha/**`, `examples/custom-captcha/**`, mock and real e2e YAML.
- Usage packets (`core_plugin_middleware.md`, `core_plugin_middleware_instance-slots.md`, config-validation) fold on implement / `opd-devdocsimpact`.
