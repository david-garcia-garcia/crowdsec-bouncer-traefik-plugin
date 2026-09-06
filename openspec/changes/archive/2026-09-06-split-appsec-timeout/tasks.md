## 1. Config

- [x] 1.1 Add `CrowdsecAppsecTimeoutMilliseconds int64` on `Config` with json `crowdsecAppsecTimeoutMilliseconds,omitempty`. Leave default 0 in `New()`.
- [x] 1.2 Add `EffectiveAppsecTimeout(*Config) time.Duration` (ms > 0 → milliseconds, else `HTTPTimeoutSeconds * time.Second`).
- [x] 1.3 Reject negative `CrowdsecAppsecTimeoutMilliseconds` in `validateParamsRequired`. Allow 0 (inherit).
- [x] 1.4 Tests: inherit 10s, override 200ms, negative rejected.

## 2. AppSec client and identity

- [x] 2.1 Set AppSec `http.Client.Timeout` from `EffectiveAppsecTimeout` in `appsec.New`. Leave LAPI and captcha on `HTTPTimeoutSeconds`.
- [x] 2.2 Hash effective AppSec timeout milliseconds on AppSec identity instead of `HTTPTimeoutSeconds`.
- [x] 2.3 Test: hanging AppSec, 50ms timeout, passthrough → allow and elapsed well under LAPI timeout.
- [x] 2.4 Test: inherit 10s and explicit 10000ms share IdentityHex; different effective timeouts do not.

## 3. Docs

- [x] 3.1 README: document `CrowdsecAppsecTimeoutMilliseconds` with inherit and 200ms recommendation; keep `HTTPTimeoutSeconds` as LAPI.
- [x] 3.2 Add the timeout contract to `knowledge/devdocs/core_plugin_appsec.md` and append `knowledge.md`.
