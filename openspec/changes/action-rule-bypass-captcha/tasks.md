## 1. Token, validation, and fold

- [ ] 1.1 `pkg/httprule/action.go`: `ActionBypassCaptcha`; `compileActionTokens` parses it and rejects it beside `captcha`; `ActionMatch.BypassCaptchaName`; `Fold` sets it before the single-reading check and clears `CaptchaName`.
- [ ] 1.2 Tests in `pkg/httprule/zzz_httprule_test.go` (token parse, `captcha` conflict, fold, ambiguous path, captcha rule on another row) and `pkg/configuration/zzz_configuration_test.go` (the `ValidateParams` error stem).

## 2. Captcha bypass in the request path

- [ ] 2.1 `pkg/bouncer/bouncer_serve_captcha.go`: predicate `bypassesCaptcha` with the TRACE; `remediateWarnCaptchaRuleOnBan` and `serveAppsecCaptchaGate` ask it.
- [ ] 2.2 `pkg/bouncer/bouncer_serve_appsec.go`, `bouncer_serve_appsec_verdict.go`: `captchaAppsecFailure` and `serveAppsecCaptchaGate` take the match; callers pass it.
- [ ] 2.3 `pkg/bouncer/bouncer_serve_lapi.go`, `origin_based_decision_remap.go`: `appliedLAPIRemediation` keeps a stored ban when the remap gives a captcha on a captcha-bypass request.
- [ ] 2.4 Tests in a new `pkg/bouncer` test file: one case per captcha source, the unchanged cases (bans, challenge, request outside the rule), the router without a captcha, and the remap edges.

## 3. Docs

- [ ] 3.1 `README.md`: section for API routes under "What you can do" (where it applies, where it does not, path matching and Traefik), `BouncerActionRules` reference, "What changed" bullet.
- [ ] 3.2 Devdocs `core_plugin_httprule.md` and `core_plugin_middleware_action-rules.md`.

## 4. Verify

- [ ] 4.1 `go test ./...` for the touched packages; lint; mutation check (bypass disabled, the new tests fail).
- [ ] 4.2 Real Traefik: a `bypassCaptcha` path rule on a router whose captcha rule would otherwise apply.
