## 1. Captcha session

- [x] 1.1 Issue `crowdsec_captcha` on valid solve (`crypto/rand` hex token; HttpOnly; Path=/; SameSite=Lax; MaxAge=grace; Secure iff TLS) and store `{remoteIP}_captcha_{token}` = `CaptchaDoneValue`
- [x] 1.2 Change `Check` to require that cookie plus GetRemoteIP; ignore `{ip}_captcha`; rand or store failure must not mark solved
- [x] 1.3 Pass `req.Request` into `Check` from `handleRemediationServeHTTP`; keep `req.remoteIP`; do not add captcha fields to `clientRequest`

## 2. Tests

- [x] 2.1 Unit tests: shared-IP without cookie unsolved; matching cookie solved; wrong cookie unsolved; cookie copied to another IP unsolved; leftover `{ip}_captcha` unsolved
