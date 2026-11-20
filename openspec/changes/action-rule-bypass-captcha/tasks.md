## 1. Token, validation, and fold

- [x] 1.1 `pkg/httprule/action.go`: `ActionBypassCaptcha`; `compileActionTokens` parses it and rejects it beside `captcha`; `ActionMatch.BypassCaptchaName`; `Fold` sets it before the single-reading check and clears `CaptchaName`.
- [x] 1.2 Tests in `pkg/httprule/zzz_httprule_test.go` (token parse, `captcha` conflict, fold, ambiguous path, captcha rule on another row) and `pkg/configuration/zzz_configuration_test.go` (the `ValidateParams` error stem).

## 2. Captcha bypass in the request path

- [x] 2.1 `pkg/bouncer/bouncer_serve_captcha.go`: predicate `bypassesCaptcha` with the TRACE; `remediateUnderActionRules` (renamed from `remediateWarnCaptchaRuleOnBan`) and `serveAppsecCaptchaGate` ask it.
- [x] 2.2 `pkg/bouncer/bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`: `captchaAppsecFailure` and `serveAppsecCaptchaGate` take the match; callers pass it.
- [x] 2.3 `pkg/bouncer/bouncer_serve_lapi.go`, `origin_based_decision_remap.go`: `appliedLAPIRemediation` keeps a stored ban when the remap gives a captcha on a captcha-bypass request.
- [x] 2.4 Tests in a new `pkg/bouncer` test file: one case per captcha source, the unchanged cases (bans, challenge, request outside the rule), the router without a captcha, and the remap edges.

## 3. Docs

- [x] 3.1 `README.md`: section for API routes under "What you can do" (where it applies, where it does not, path matching and Traefik), `BouncerActionRules` reference, "What changed" bullet.
- [x] 3.2 Devdocs `core_plugin_httprule.md` and `core_plugin_middleware_action-rules.md`.

## 4. Verify

- [x] 4.1 `go test ./...` (Go 1.25.6, and the touched packages on Go 1.22.12); `golangci-lint run`; mutation check (predicate off, `CaptchaName` kept, remap exception off, token read after the single-reading check: the new tests fail each time).
- [x] 4.2 Real Traefik v3.7.11 and v3.7.19 (Yaegi): a site-wide `captcha` rule plus `{path: "^/api/", action: [bypassCaptcha]}`. `/api/items` and `/api/items%20x` reach the backend; `/catalog`, `/api/../catalog` and `/api/%2e%2e/catalog` do not; `/api/..%2Fcatalog` and `/api/..%5Ccatalog` reach the backend unchanged, as the README states.
