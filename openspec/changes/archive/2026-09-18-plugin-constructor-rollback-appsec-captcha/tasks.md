## 1. Reproduce on master first

- [x] 1.1 Stream mode plus an AppSec client certificate that fails `tls.X509KeyPair`: `New` errors, the stream ticker keeps polling
- [x] 1.2 `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false`: `New` succeeds, no warning in the log file
- [x] 1.3 Appsec mode with `crowdsecAppsecFailureAction: captcha` and an AppSec 500: client gets a ban, not a challenge
- [x] 1.4 After `New`, the caller's `*Config` carries the upper-cased `logLevel` and the resolved LAPI key

## 2. Constructor rollback

- [x] 2.1 Named `err` return on `New` plus `bindCtx, releaseHolders := context.WithCancel(ctx)` and a `defer` that releases only when `err != nil`
- [x] 2.2 Pass `bindCtx` to `lapi.OpenStream`, `lapi.OpenLive`, and `appsec.Open`
- [x] 2.3 Prove the success path still holds, and that cancelling the constructor ctx still releases

## 3. Appsec-mode-without-AppSec warning

- [x] 3.1 `ValidateParams` emits a `WARN` naming both keys and the consequence, and still returns nil
- [x] 3.2 Unit test in `pkg/configuration`, plus a root test that finds it in the operator's log file

## 4. README axes

- [x] 4.1 Say that `crowdsecMode` and `crowdsecAppsecEnabled` are independent axes, that `appsec` plus disabled enforces nothing, and that the plugin warns. Keep the existing mode table shape

## 5. Captcha in appsec mode

- [x] 5.1 Initialise the captcha client when appsec mode's effective AppSec failure action is `captcha`; condition the early return on it
- [x] 5.2 Test an AppSec 500 in appsec mode serving the challenge

## 6. Config snapshot

- [x] 6.1 `prepared := *config`, pass `&prepared` onwards, comment the shared slice and map fields
- [x] 6.2 Test that the caller's struct is unchanged. Drop this deliverable if it needs test changes beyond the constructor
  Kept: no test outside `zzz_constructor_test.go` changed. The edit is wider than #22's three lines only because every `config.` inside `New` became `prepared.`

## 7. Spec and docs

- [x] 7.1 `core_plugin_middleware_bouncer`: rollback requirement, no-mutation requirement, and reword the constructor-ctx scenario
- [x] 7.2 `core_plugin_middleware_config-validation`: the warning
- [x] 7.3 `core_plugin_appsec_failure-action`: captcha in appsec mode

## 8. Verify

- [x] 8.1 `go build ./...`, `go vet ./...`, `go test ./pkg/... -count=1`
- [x] 8.2 `go test . -count=1` and `yaegi test -v .` at v0.16.1 — the named-return `defer` under the interpreter is the known risk
- [x] 8.3 `golangci-lint run ./...`
- [x] 8.4 Docker `go test -race -count=1 ./pkg/...`
- [ ] 8.5 CI on the pushed head, including `e2e (docker + pester)`, compared against the previous head's conclusions
