# Explore

## Concepts

Units this change would touch:

| Unit | Path | Job |
| --- | --- | --- |
| Captcha Client | `pkg/captcha/captcha.go` | Published reclaim value: challenge page, token check, gate mint. `New` is the only provider/key-type switch. |
| Siteverify | `pkg/captcha/captcha.go` (`postSiteverify`, `responseProvider`) | Today's `secret`+`response`+`success` POST. Stays the verifier for hCaptcha, classic `recaptcha`, Turnstile, `custom`. |
| Assessment | not in tree | New verifier for `recaptcha-enterprise`. `Pass(token, remoteIP)` against Cloud assessments. |
| Widget | not in tree | Challenge-page data: script URL, CSS class, token field, action, boot script, retry-after-reject. |
| Config validation | `pkg/configuration/configuration.go` | Provider allowlist, `validateCaptchaCredentials`, `GetVariable` file-then-field. |
| Ownership | `pkg/captcha/session.go` (`ownership`) | Reclaim key. Enterprise knobs join this payload so a change reclaims. |
| Stock page | `captcha.html` | One bundled template. Gains boot / action / checkbox placeholders. |
| Captcha request routing | `pkg/bouncer/bouncer.go` | Unchanged. Still `Check` then `ServeHTTP(rw, r, req.remoteIP, header)`. Field name stays `g-recaptcha-response`. |
| Captcha gate cookie | `pkg/captcha/gate.go` | Unchanged. Mint only on Pass. |
| GetRemoteIP | `pkg/ip/checker.go` | Owner of the client address. Already on `clientRequest.remoteIP` before captcha runs. |

```
bouncer.ServeHTTP
    │
    ├─ GetRemoteIP → clientRequest.remoteIP     (owner; captcha does not re-parse)
    │
    └─ handleRemediationServeHTTP
           ├─ Check(gate, remoteIP) → WriteSolvedRedirect
           └─ captcha.ServeHTTP(rw, r, remoteIP, header)
                  │
                  ├─ Validate(r, remoteIP)          (no provider name)
                  │     ├─ no POST / empty field → None
                  │     └─ verifier.Pass(token, remoteIP)
                  │           ├─ siteverify  → success
                  │           └─ assessment  → valid, then action, then min score
                  │
                  ├─ Pass   → mint crowdsec_captcha_gate, solved-captcha, 302
                  ├─ None or Error → render + boot
                  ├─ Reject + widget retry     → render + boot   (checkbox)
                  └─ Reject + widget no-retry  → render, omit boot (score)
```

`New` pairs one widget with one verifier. `ServeHTTP` and `Validate` read those fields only.

Call sites that matter (bounded ranks below):

- `Client.Validate`: 1 production (`ServeHTTP` in `pkg/captcha/captcha.go`), 4 tests in `pkg/captcha/zzz_validate_body_test.go`. Roots searched: worktree `*.go` for `.Validate(` and `func (c *Client) Validate`.
- `Client.New`: 1 production (`newOwnerClient` in `pkg/captcha/session.go`), 13 tests under `pkg/captcha/zzz_*.go`. Roots searched: `pkg/captcha` for `client.New(` / `func (c *Client) New`.
- `postSiteverify`: 1 caller (`Validate`). Roots searched: `pkg/captcha`.
- `validateCaptchaCredentials`: 1 production caller (`validateCaptchaCredentialsAndTemplates`). Roots searched: `pkg/configuration`.
- `captcha.ServeHTTP` from bounce: 1 (`pkg/bouncer/bouncer.go`). Out of scope to change.

Reproduce: no claimed failure (feature add). not reproduced.

Outside facts used:

- In-tree: `knowledge/research/ext_recaptcha_siteverify/`, `knowledge/research/ext_traefik_plugins_config-decode/`, `knowledge/devdocs/core_plugin_middleware_captcha-siteverify.md`, `core_plugin_middleware_captcha-routing.md`, `core_plugin_middleware_captcha-gate.md`, `core_plugin_ip.md`.
- Research: `knowledge/research/ext_recaptcha_enterprise_assessments/`, `knowledge/research/ext_recaptcha_enterprise_widget/`.

## Decisions

- Seam: add Widget + Verifier on the Client. `New` is the only switch (`recaptcha-enterprise` + `checkbox`/`score` vs today's `infoProviders` / `custom`). `ServeHTTP` and `Validate` do not mention a provider.
- Siteverify stays one implementation and keeps form-versus-JSON, `remoteip` omitempty, and `success` only. Do not change hCaptcha, Turnstile, classic `recaptcha`, or `custom`.
- Assessment is the second `Pass` implementation: `POST` JSON to `https://recaptchaenterprise.googleapis.com/v1/projects/{project}/assessments` on the existing siteverify `http.Client` and timeout. No Google client library.
- Auth: `X-Goog-Api-Key` header, never the query string, never logged. If the delegated assessments notes later show the endpoint rejects that header, stop (query string and OAuth are out of scope).
- `Validate` result is `(Outcome, error)`: `None` (not POST or empty token), `Pass`, `Reject`. Error stays the error return (`(None, err)` is unused — return `(_, err)`). `Verifier.Pass` stays `(bool, error)`.
- Assessment classify: non-2xx, missing/non-JSON body, or a Google error envelope without `tokenProperties` → Error. Successful Assessment with `tokenProperties.valid == false` → Reject. Do not treat a Google error envelope as Reject. Action compare is case-insensitive.
- Siteverify Content-Type miss stays `(false, nil)` inside Pass (live siteverify spec). “Same as siteverify `(false, err)`” is JSON `Decode` / transport only.
- Stock `captcha.html` stays one file. Template map keeps `SiteKey`, `FrontendJS`, `FrontendKey`, `ChallengeURL` and gains `BootScript`, `Action`, `DrawCheckbox`. Checkbox operators who omit the new keys still work if `FrontendJS` is `enterprise.js`.
- `captchaEnterpriseMinScore` is a `string` on `Config` (this plugin has no `float64` knobs; Traefik decode is weakly typed). Parse at `ValidateParams`. Empty = omit (checkbox). Score requires a parsed value `> 0` and `<= 1`.
- `CaptchaSecretKey` is not required when the provider is `recaptcha-enterprise`. Site key and gate secret stay required. Live SHALL on `core_plugin_middleware_config-validation` is the freeze this change replaces.
- Live siteverify spec stays the siteverify contract. Assessments is a new live promise (FindSpecHost at propose), not a silent widen of `success`.
- Rejected: route enterprise through `custom` (body and `success` cannot express assessments).
- Rejected: replace classic `recaptcha` or send a migrated classic key to assessments.
- Rejected: grow `Client.New`'s positional list; pass enterprise knobs as a named construction value `New` already switches on.
- Rejected: service-account / OAuth, policy-based third widget, score on other providers, gate/routing/`IsCaptchaFormPost` changes.
- Live contract: `openspec/specs/core_plugin_middleware_config-validation/spec.md` (secret-always-required SHALL). `openspec/specs/core_plugin_middleware_captcha-siteverify/spec.md` (built-in siteverify freeze). No assessments spec yet.

## Open questions

- Q: What Go result does Validate expose for None / Pass / Reject / Error without ServeHTTP branching on provider?
  Rank: bounded asked — changes existing Validate (bool, error); 1 production caller (ServeHTTP) and 4 tests in pkg/captcha/zzz_validate_body_test.go (roots worktree *.go)
  Decision: assumed — (Outcome, error) with None, Pass, Reject. Error is the error return. Verifier.Pass stays (bool, error). ServeHTTP switches on Outcome plus widget.retry.
  By: explore

- Q: Who already owns the client address used as event.userIpAddress?
  Rank: additive asked — new assessment field this change creates; Request path / Verifiers say send the client address when non-empty
  Decision: resolved — owner is GetRemoteIP / clientRequest.remoteIP (pkg/ip/checker.go, pkg/bouncer/bouncer.go). Reuse the remoteIP already passed into Validate / Pass. Do not parse X-Forwarded-For, X-Real-Ip, or RemoteAddr in captcha.
  By: explore

- Q: Does assessments accept X-Goog-Api-Key, or only ?key=?
  Rank: additive asked — new assessment request this change creates; Verifiers require the header after one check
  Decision: resolved — send X-Goog-Api-Key only. Cloud system parameters list that header as the HTTP form of key across Google REST APIs (knowledge/research/ext_recaptcha_enterprise_assessments/). The reCAPTCHA sample only shows ?key=. Do not put the key in the query string. Do not log it.
  By: explore

- Q: What are the assessment JSON names, score type/range, and HTTP status for an invalid token vs a bad API key?
  Rank: additive asked — new decoder this change creates; Verifiers name tokenProperties.valid, action, and riskAnalysis.score
  Decision: resolved — request event.token, event.siteKey, optional event.userIpAddress, optional event.expectedAction. Pass order is tokenProperties.valid, then action when configured, then riskAnalysis.score (JSON number 0.0-1.0) when a minimum is set. Invalid token is a successful Assessment with valid false (Reject), not an HTTP error. Bad API key status is not stated by Google; treat non-2xx or a Google error envelope as Error. Source ext_recaptcha_enterprise_assessments/.
  By: explore

- Q: Does enterprise checkbox still use g-recaptcha, g-recaptcha-response, and data-callback on enterprise.js?
  Rank: additive asked — new checkbox widget this change creates; Widgets table names those tokens
  Decision: resolved — yes. Script https://www.google.com/recaptcha/enterprise.js (no render=), class g-recaptcha, data-sitekey, optional data-action, field g-recaptcha-response. JS API names data-callback on successful response. Retry after reject. Source ext_recaptcha_enterprise_widget/.
  By: explore

- Q: What is the score-key boot, and must a refused token omit the script to avoid another execute?
  Rank: additive asked — new score widget this change creates; Widgets and ServeHTTP name grecaptcha.enterprise.ready / execute and omit boot on reject
  Decision: resolved — script enterprise.js?render={siteKey}. Boot is fixed Go text (grecaptcha.enterprise.ready then execute(siteKey, {action}), write g-recaptcha-response, submit). Official docs do not say to omit the script after a refused score; this change still omits the boot on Reject so the page does not auto-execute again. Source ext_recaptcha_enterprise_widget/.
  By: explore

- Q: How is captchaEnterpriseMinScore typed, and what does greater than zero mean at the boundary?
  Rank: additive asked — new Config knob this change creates; Config table names the knob and greater than zero
  Decision: assumed — string on Config (no existing float knobs; Traefik WeaklyTypedInput will coerce a YAML number). Empty after trim means omit (checkbox only). Score parses float64 and requires greater than 0 and at most 1. Zero, negative, 1.1, and non-numeric fail ValidateParams.
  By: explore

- Q: How does action string equality work (case, empty vs omitted expectedAction)?
  Rank: additive asked — new assessment check this change creates; Verifiers say compare when an action is configured
  Decision: resolved — compare tokenProperties.action to the configured action case-insensitively (official action names are not case-sensitive). Empty after trim omits event.expectedAction and skips the check (checkbox). Score requires a non-empty action at ValidateParams. Source ext_recaptcha_enterprise_assessments/ (Action names).
  By: explore

- Q: What is the operator blast radius of dropping the live SHALL that always requires CaptchaSecretKey?
  Rank: bounded asked — changes validateCaptchaCredentials (1 production caller) and live core_plugin_middleware_config-validation (roots pkg/configuration); Config says do not require the secret for this provider
  Decision: assumed — skip the empty-secret reject only when captchaProvider is recaptcha-enterprise. hCaptcha, classic recaptcha, Turnstile, and custom still require it. Site key and gate secret stay required. Operators on those providers are unchanged.
  By: explore

- Q: When a missing or non-JSON assessment body arrives, is that Error or the siteverify Content-Type miss (false, nil)?
  Rank: additive asked — new assessment classify this change creates; Verifiers say missing/non-JSON is Error; Tensions flag the siteverify clash
  Decision: assumed — assessment is Error. Siteverify keeps today's Content-Type miss as Pass-false with no error (out of scope to change). Same as siteverify (false, err) applies to transport and JSON Decode only.
  By: explore

- Q: What names do Widget, Verifier, and Assessment keep?
  Rank: additive asked — new units this change creates; Request path / Verifiers / Widgets name them
  Decision: assumed — keep those three names. Do not write Language until the types exist on a path. Usage packet core_plugin_middleware_captcha-siteverify stays the siteverify owner; assessments get their own packet later.
  By: explore

- Q: What placeholder names does the stock template gain?
  Rank: additive asked — template data this change creates; Widgets name boot, action, and whether to draw the checkbox
  Decision: assumed — BootScript, Action, DrawCheckbox next to the existing SiteKey, FrontendJS, FrontendKey, ChallengeURL. Map stays map[string]string. DrawCheckbox is non-empty when the checkbox div should render.
  By: explore
