## 1. Reproduce on master first

- [ ] 1.1 Stream mode plus an AppSec client certificate that fails `tls.X509KeyPair`: `New` errors, the stream ticker keeps polling
- [ ] 1.2 `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false`: `New` succeeds, no warning in the log file
- [ ] 1.3 Appsec mode with `crowdsecAppsecFailureAction: captcha` and an AppSec 500: client gets a ban, not a challenge
- [ ] 1.4 After `New`, the caller's `*Config` carries the upper-cased `logLevel` and the resolved LAPI key

## 2. Constructor rollback

- [ ] 2.1 Named `err` return on `New` plus `bindCtx, releaseHolders := context.WithCancel(ctx)` and a `defer` that releases only when `err != nil`
- [ ] 2.2 Pass `bindCtx` to `lapi.OpenStream`, `lapi.OpenLive`, and `appsec.Open`
- [ ] 2.3 Prove the success path still holds, and that cancelling the constructor ctx still releases

## 3. Appsec-mode-without-AppSec warning

- [ ] 3.1 `ValidateParams` emits a `WARN` naming both keys and the consequence, and still returns nil
- [ ] 3.2 Unit test in `pkg/configuration`, plus a root test that finds it in the operator's log file

## 4. README axes

- [ ] 4.1 Say that `crowdsecMode` and `crowdsecAppsecEnabled` are independent axes, that `appsec` plus disabled enforces nothing, and that the plugin warns. Keep the existing mode table shape

## 5. Captcha in appsec mode

- [ ] 5.1 Initialise the captcha client when appsec mode's effective AppSec failure action is `captcha`; condition the early return on it
- [ ] 5.2 Test an AppSec 500 in appsec mode serving the challenge

## 6. Config snapshot

- [ ] 6.1 `prepared := *config`, pass `&prepared` onwards, comment the shared slice and map fields
- [ ] 6.2 Test that the caller's struct is unchanged. Drop this deliverable if it needs test changes beyond the constructor

## 7. Spec and docs

- [ ] 7.1 `core_plugin_middleware_bouncer`: rollback requirement, no-mutation requirement, and reword the constructor-ctx scenario
- [ ] 7.2 `core_plugin_middleware_config-validation`: the warning
- [ ] 7.3 `core_plugin_appsec_failure-action`: captcha in appsec mode

## 8. Verify

- [ ] 8.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`
- [ ] 8.2 `go test . -count=1` and `yaegi test -v .` at v0.16.1 — the named-return `defer` under the interpreter is the known risk
- [ ] 8.3 `golangci-lint run ./...`
- [ ] 8.4 Docker `go test -race -count=1 ./pkg/...`
- [ ] 8.5 CI on the pushed head, including `e2e (docker + pester)`, compared against the previous head's conclusions
