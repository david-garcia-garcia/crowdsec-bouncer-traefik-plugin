## 1. Terminate unanswered challenge paths

- [x] 1.1 In `pkg/bouncer/bouncer.go` `serveAppSec`, after the captcha-rule and SkipAppsec branches, when AppSec is subscribed and `applyAppsecServeHTTP` returns false and `req.URL.Path` has prefix `/crowdsec-internal/challenge/`, call `http.NotFound(rw, req.Request)` and return true. Do not 404 inside `applyAppsecServeHTTP`. Do not add a trusted-IP check here.

## 2. Prove the gate

- [x] 2.1 In `pkg/bouncer/zzz_bouncer_test.go`, add a regression next to `TestHandleNextServeHTTPAllowCallsNext`: AppSec HTTP 200 `{"action":"allow"}` on `GET /crowdsec-internal/challenge/custom.js` is 404 and `next` is not called; the same allow on a normal path still calls `next`.

## 3. Docs

- [x] 3.1 Update the README bot-detection sentence that says the prefix is safe whenever the middleware covers the host: host-wide coverage still must not forward unanswered `/crowdsec-internal/challenge/` to origin (the bouncer 404s). Keep the extra router note for middleware that only covers some paths.
- [x] 3.2 Update `knowledge/devdocs/core_plugin_appsec.md` How-to-use allow bullet: allow or empty 200 → `next` except `/crowdsec-internal/challenge/`, which 404s when AppSec did not write a relay or ban.

## 4. Verify

- [x] 4.1 `go test ./pkg/bouncer/` on this machine.
