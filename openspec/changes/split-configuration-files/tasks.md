## 1. Split pkg/configuration files

- [ ] 1.1 Add `config.go` with Config, New, existing enums, EffectiveFailureAction
- [ ] 1.2 Add `secrets.go` with GetVariable
- [ ] 1.3 Add `template.go` with GetTemplate and getContentTypeFromPath
- [ ] 1.4 Add `validate.go` with ValidateParams and helpers including validateParamsTLS
- [ ] 1.5 Delete `configuration.go`

## 2. Move runtime TLS next to HTTP clients

- [ ] 2.1 Add `pkg/crowdsecconnection/tls.go` with unexported getTLSConfig and getTLSConfigCrowdsec (same behaviour as dest master)
- [ ] 2.2 Point `New` at the local builder; drop `configuration.GetTLSConfigCrowdsec`
- [ ] 2.3 Move `Test_GetTLSConfigCrowdsec` and `validPEM` into `pkg/crowdsecconnection`; leave other tests in `configuration_test.go`

## 3. Verify

- [ ] 3.1 `go test ./pkg/configuration/ ./pkg/crowdsecconnection/ ./pkg/captcha/ ./pkg/bouncer/`
- [ ] 3.2 Grep product paths for `GetTLSConfigCrowdsec` and `configuration.go` (not archive, not devstate)
