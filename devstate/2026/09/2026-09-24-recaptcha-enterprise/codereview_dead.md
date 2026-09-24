# Dead

1. [hard] Leftover production path — `pkg/captcha/captcha.go:25` — `Client.secretKey` has no production reader after siteverify moved to `siteverifyVerifier`
   Quote:
      ```
      secretKey           string
      ...
      c.secretKey = secretKey
      c.verifier = newSiteverifyVerifier(httpClient, secretKey, ...)
      ```
   Note:
      ```
      grep secretKey -- glob *.go
      Production reads only siteverifyVerifier.secretKey (siteverify.go) and New's secretKey param.
      Only remaining Client.secretKey hit is zzz_siteverify_test.go:75.
      ```
   Fix: Delete `Client.secretKey`; assert the posted secret via `siteverifyVerifier` or the value passed to `New`
   Status: done
   Argument: deleted Client.secretKey; siteverify test asserts the New secret.
