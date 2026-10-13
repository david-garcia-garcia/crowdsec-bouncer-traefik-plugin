## 1. Relay drop skip

- [ ] 1.1 In `handleAppsecResponseServeHTTP`, skip `recordDropped` when `req.URL.Path` has prefix `/crowdsec-internal/challenge/`; leave ban and captcha call sites unchanged
- [ ] 1.2 Add a bouncer test using `TestDroppedCount`: challenge envelope on `/protected` increments origin `appsec` by 1; the same envelope on `/crowdsec-internal/challenge/submit` does not

## 2. Spec and proof

- [ ] 2.1 Keep the delta on `core_plugin_appsec_bot-detection`; do not edit `.github/workflows` or add a JSON parser
- [ ] 2.2 Run `go test ./pkg/bouncer/...` on this machine
