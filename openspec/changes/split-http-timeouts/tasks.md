## 1. Config knobs and inherit

- [x] 1.1 Add `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, and `CaptchaSiteverifyHTTPTimeoutSeconds` on `Config` with JSON tags `crowdsecLapiHttpTimeoutSeconds`, `crowdsecAppsecHttpTimeoutSeconds`, `captchaSiteverifyHttpTimeoutSeconds`; leave them at 0 in `configuration.New`
- [x] 1.2 Add `(*Config) EffectiveHTTPTimeoutSeconds(override int64) int64` next to `EffectiveFailureAction`: return `HTTPTimeoutSeconds` when `override == 0`, else `override`
- [x] 1.3 Put the three new knobs in `requiredInt0`; keep `HTTPTimeoutSeconds` in `requiredInt1`

## 2. Wire existing clients

- [x] 2.1 LAPI `newTransport`: set `http.Client.Timeout` and stored `httpTimeoutSeconds` from `EffectiveHTTPTimeoutSeconds(CrowdsecLapiHTTPTimeoutSeconds)`
- [x] 2.2 AppSec `newTransport`: same with `CrowdsecAppsecHTTPTimeoutSeconds`
- [x] 2.3 `bouncer.New` captcha `http.Client` Timeout from `EffectiveHTTPTimeoutSeconds(CaptchaSiteverifyHTTPTimeoutSeconds)`
- [x] 2.4 Add `HTTPClientForTest` on `captcha.Client` (test in the name)

## 3. Docs

- [x] 3.1 Reword README `HTTPTimeoutSeconds` to the shared default (LAPI, AppSec, captcha siteverify)
- [x] 3.2 Document the three knobs; example `crowdsecAppsecHttpTimeoutSeconds: 1` with `crowdsecAppsecFailureAction: passthrough`

## 4. Tests

- [x] 4.1 Inherit helper: omit/0 → 10; positive override wins; negative knob fails `cannot be less than 0`; `HTTPTimeoutSeconds` 0 still fails `< 1`
- [x] 4.2 LAPI adopt: LAPI override 30 Adopts Timeout 30s; shared-default change with override 0 Adopts; override 10 vs inherit 10 does not replace
- [x] 4.3 AppSec `Query` through `New`/`Open` against a hanging listener, override 1s + passthrough, returns well under 10s
- [x] 4.4 Bouncer captcha: provider set, override 1 → Timeout 1s; override 0 → Timeout 10s
- [x] 4.5 `SessionKey` / `IdentityHex` / live `Key` / AppSec `Key` unchanged when only timeout knobs differ

## 5. Verify

- [x] 5.1 `go test ./pkg/configuration/ ./pkg/lapi/ ./pkg/appsec/ ./pkg/bouncer/ ./pkg/captcha/` and `golangci-lint run` on those packages
