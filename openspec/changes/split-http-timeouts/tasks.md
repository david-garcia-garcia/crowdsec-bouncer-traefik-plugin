## 1. Config knobs and inherit

- [ ] 1.1 Add `CrowdsecLapiHTTPTimeoutSeconds`, `CrowdsecAppsecHTTPTimeoutSeconds`, and `CaptchaSiteverifyHTTPTimeoutSeconds` on `Config` with JSON tags `crowdsecLapiHttpTimeoutSeconds`, `crowdsecAppsecHttpTimeoutSeconds`, `captchaSiteverifyHttpTimeoutSeconds`; leave them at 0 in `configuration.New`
- [ ] 1.2 Add `(*Config) EffectiveHTTPTimeoutSeconds(override int64) int64` next to `EffectiveFailureAction`: return `HTTPTimeoutSeconds` when `override == 0`, else `override`
- [ ] 1.3 Put the three new knobs in `requiredInt0`; keep `HTTPTimeoutSeconds` in `requiredInt1`

## 2. Wire existing clients

- [ ] 2.1 LAPI `newTransport`: set `http.Client.Timeout` and stored `httpTimeoutSeconds` from `EffectiveHTTPTimeoutSeconds(CrowdsecLapiHTTPTimeoutSeconds)`
- [ ] 2.2 AppSec `newTransport`: same with `CrowdsecAppsecHTTPTimeoutSeconds`
- [ ] 2.3 `bouncer.New` captcha `http.Client` Timeout from `EffectiveHTTPTimeoutSeconds(CaptchaSiteverifyHTTPTimeoutSeconds)`
- [ ] 2.4 Add `HTTPClientForTest` on `captcha.Client` (test in the name)

## 3. Docs

- [ ] 3.1 Reword README `HTTPTimeoutSeconds` to the shared default (LAPI, AppSec, captcha siteverify)
- [ ] 3.2 Document the three knobs; example `crowdsecAppsecHttpTimeoutSeconds: 1` with `crowdsecAppsecFailureAction: passthrough`

## 4. Tests

- [ ] 4.1 Inherit helper: omit/0 → 10; positive override wins; negative knob fails `cannot be less than 0`; `HTTPTimeoutSeconds` 0 still fails `< 1`
- [ ] 4.2 LAPI adopt: LAPI override 30 Adopts Timeout 30s; shared-default change with override 0 Adopts; override 10 vs inherit 10 does not replace
- [ ] 4.3 AppSec `Query` through `New`/`Open` against a hanging listener, override 1s + passthrough, returns well under 10s
- [ ] 4.4 Bouncer captcha: provider set, override 1 → Timeout 1s; override 0 → Timeout 10s
- [ ] 4.5 `SessionKey` / `IdentityHex` / live `Key` / AppSec `Key` unchanged when only timeout knobs differ

## 5. Verify

- [ ] 5.1 `go test ./pkg/configuration/ ./pkg/lapi/ ./pkg/appsec/ ./pkg/bouncer/ ./pkg/captcha/` and `golangci-lint run` on those packages
