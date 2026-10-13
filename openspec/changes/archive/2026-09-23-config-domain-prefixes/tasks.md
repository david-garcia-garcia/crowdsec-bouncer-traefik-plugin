## 1. Configuration surface

- [x] 1.1 Rename every public `Config` Go field and JSON tag to `lapi*` / `appsec*` / `bouncer*` per requirement tables. Leave `logLevel`, `logFormat`, `logFilePath`, and `reclaimGraceSeconds` unprefixed. No old-key aliases.
- [x] 1.2 Delete `HTTPTimeoutSeconds`, `httpTimeoutSeconds`, and `EffectiveHTTPTimeoutSeconds`. Add `LapiHTTPTimeoutSeconds`, `AppsecHTTPTimeoutSeconds`, and `BouncerCaptchaSiteverifyHTTPTimeoutSeconds` default 10, `requiredInt1` (`cannot be less than 1`).
- [x] 1.3 Update `GetVariable` production strings and TLS prefix helpers (`Lapi`/`Appsec` + `TLSCertificateAuthority` / `TLSClientCertificate` / `TLSClientKey`). Validation errors name the new Go fields.
- [x] 1.4 Update `.traefik.yml` `testData` (`BouncerEnabled`, `LapiKey`) and `plugin.go` comments.

## 2. LAPI package boundary

- [x] 2.1 In `pkg/lapi/identity.go` only: drop redundant `lapi` JSON prefix (`scheme`/`host`/`path`/`key`); rename TLS to `tlsClientCertificate` / `tlsClientKey`; drop public `lapi`/`crowdsec` syllables on Redis and CAPI JSON. Do not add a second hash.
- [x] 2.2 Identity / ownership / session / transport / Redis `storeParams` use local names (`Scheme`, `Host`, `Key`, `TLSClientCertificate`, `HTTPTimeoutSeconds`, Redis `Enabled`/`Host`/`ReadHosts`/`Password`/`Database`).
- [x] 2.3 `newTransport` reads `config.LapiHTTPTimeoutSeconds` only. Timeout change Opens a new Client (ownership key includes the knob). Delete inherit-helper call sites.

## 3. AppSec package boundary

- [x] 3.1 In `pkg/appsec/session.go` only: rename `tlsCertificateBouncer` → `tlsClientCertificate` / `tlsClientKey`. Do not add a second hash.
- [x] 3.2 Transport fields use `TLSClientCertificate` / `TLSClientKey`. `newTransport` reads `config.AppsecHTTPTimeoutSeconds` only.
- [x] 3.3 `appsec.Prepare` still copies omitted scheme/key from LAPI when AppSec is owned. It MUST NOT copy the timeout.

## 4. Bouncer

- [x] 4.1 Rename `streamStartupBlock` → `startupBlock`. Keep `lapiFailureAction` / `appsecFailureAction`. Wire public `Bouncer*` fields at `bouncer.New`.
- [x] 4.2 Captcha siteverify `http.Client` Timeout is `BouncerCaptchaSiteverifyHTTPTimeoutSeconds`. Pass `BouncerCaptcha*` into existing `siteKey` / `secretKey` / `gateSecret` args. Do not grow a `bouncer` field on `pkg/captcha`.
- [x] 4.3 Copy `LapiDefaultDecisionSeconds` onto `Bouncer.defaultDecisionSeconds` and pass that into `LiveLookup`.

## 5. Tests and operator files

- [x] 5.1 Update unit tests that name old fields, inherit timeout, or `EffectiveHTTPTimeoutSeconds` (`pkg/configuration`, `pkg/lapi`, `pkg/appsec`, `pkg/bouncer`).
- [x] 5.2 Rewrite README, `examples/**` plugin YAML/labels, mock dynamics, and real e2e compose/file-provider YAML to the new keys. Real e2e `httpTimeoutSeconds: 60` becomes both new knobs set to 60.
- [x] 5.3 Leave `knowledge/devdocs` Language/usage folds for implement / `opd-devdocsimpact` (deltas already shown in explore). Do not add `docs/config-domain-prefixes.md`.
