## 1. Configuration

- [x] 1.1 Add `CrowdsecDecisionHeader` string on `Config` (`json:"crowdsecDecisionHeader,omitempty"`), default empty in `New()`
- [x] 1.2 Test: CreateConfig / New default empty; whitespace-only treated as off at use time (no ValidateParams error)

## 2. Origin constant

- [x] 2.1 Add `OriginPluginForcedDecision = "plugin:forced_decision"` beside the other `OriginPlugin*` constants
- [x] 2.2 Include it in the metrics test origin list if that table is exhaustive

## 3. ServeHTTP

- [x] 3.1 After trusted-client skip, `b` remediates without lookup; `c` is merged after lookup so a stream/live ban wins with WARN
- [x] 3.2 Store the trimmed header name on Bouncer in `New` (do not put it on `clientRequest`)
- [x] 3.3 Tests: feature off ignores `X-Crowdsec-Decision: c`; `c` captchas when lookup is not ban; `c` loses to a stream ban with WARN; `b` bans without lookup; `t`/`B`/empty fall through; trusted IP skips force; gated cookie + `c` reaches next when lookup is not ban; `appsec` mode still honors `c`
- [x] 3.4 Header `c` still looks up; stream/live/fail-closed ban wins and WARN `ServeHTTP:forcedCaptchaSuperseded`

## 4. Docs

- [x] 4.1 README: `crowdsecDecisionHeader` empty = off; example `X-Crowdsec-Decision` with values `b`/`c`; captcha gate still applies; earlier middleware must set the header
- [x] 4.2 Traefik example snippet if README already shows a headers-middleware chain

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/bouncer ./pkg/configuration ./pkg/lapi ./pkg/decisionscope`, `go test .`, `golangci-lint run ./...`
