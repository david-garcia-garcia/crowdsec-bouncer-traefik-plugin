## 1. Ownership payload

- [ ] 1.1 Add `LogFilePath`, `LogFormat`, and `LogLevel` to unexported `ownership` in `pkg/captcha/session.go` as a `Log*` block (same stem order as Config). Copy `cfg.LogFilePath`, `cfg.LogFormat`, and `cfg.LogLevel` as stored in `ownershipFrom`. Do not restyle the rest of the struct. Do not change `Open`, `bindIdentity`, `Client.New`, LAPI, AppSec, `pkg/logger`, or `plugin.go` logger construction.

## 2. Tests

- [ ] 2.1 Add `TestOwnershipKey_LogConfigChangeReclaims` next to `TestOwnershipKey_EnterpriseKnobChangeReclaims` in `pkg/captcha/zzz_owner_test.go`. Assert `OwnershipKey` changes when `LogLevel`, `LogFilePath`, or `LogFormat` differs. Keep `TestOwnershipKey_ExcludesSlotAndBounce` passing.

## 3. Verify

- [ ] 3.1 `go test ./pkg/captcha/` and `golangci-lint run ./pkg/captcha/...`
