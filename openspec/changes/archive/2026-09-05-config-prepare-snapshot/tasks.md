## 1. Copy then mutate in New

- [x] 1.1 In `plugin.go` `New`, shallow-copy `*config` into a local snapshot before any field write
- [x] 1.2 Apply LogLevel ToUpper and Ban/Captcha HTML path aliases on the snapshot only; build the logger from ToUpper without writing Traefik’s pointer
- [x] 1.3 Pass the snapshot to `ValidateParams`, `Prepare`, `Key`, `crowdsecconnection.New`, and `bouncer.New`

## 2. Tests

- [x] 2.1 Add a test that after `New`, the caller Config still has mixed-case LogLevel and does not receive BanFilePath from BanHTMLFilePath
- [x] 2.2 Keep existing same-connection / isolated-LAPI tests passing (identity still hashes prepared secrets and CAPI rewrite)

## 3. Verify

- [x] 3.1 `go test ./...` for packages touched (`plugin_test.go`, crowdsecconnection, bouncer as needed)
- [x] 3.2 `go vet` on those packages
