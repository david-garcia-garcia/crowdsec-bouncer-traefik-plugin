## 1. Configuration

- [x] 1.1 Add `ForwardedHeadersInsecure` between the existing forwarded-header fields; default false in `New()`
- [x] 1.2 Tests: default false; flag plus valid list accepted; flag plus bad CIDR still fails

## 2. GetRemoteIP

- [x] 2.1 Add `insecure bool`; keep the default path bit for bit
- [x] 2.2 Insecure path: no `getIP`, no checker, whole trimmed header
- [x] 2.3 Grow `TestGetRemoteIP` with an `insecure` column (flag-off regression + flag-on cases)

## 3. Bouncer

- [x] 3.1 Resolve effective header in `New`; Info log; pass the flag into `GetRemoteIP`
- [x] 3.2 Test default name → `X-Real-Ip`; explicit non-default name unchanged

## 4. Specs and docs

- [x] 4.1 Prefix the existing radix-lookup SHALL; add the insecure requirement + scenarios
- [x] 4.2 Update `knowledge/devdocs/core_plugin_ip.md` Language and Gotchas
- [x] 4.3 README forwarded-headers option entries + new knob

## 5. Verify

- [x] 5.1 `go build ./...`, `go vet ./...`, `go test ./pkg/...`, `go test .`, `golangci-lint run ./...`
