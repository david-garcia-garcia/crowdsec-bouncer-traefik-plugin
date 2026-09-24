# Explore

## Concepts

A bouncing router must start when the captcha page or the ban page cannot be loaded. Dest fails `New` for a missing captcha file and stays silent on an empty ban path. The ask is startup-only warn, no bundled page, captcha remediations fall back to ban, ban stays a status with an empty body.

### Reproduce

**Reproduced.** Missing captcha file fails `New`. Empty ban path is silent. GET ban with a nil template has an empty 403 body.

- `go test -count=1 -timeout 120s -run 'TestNew_RejectsEmptyCaptchaFilePath|Test_ValidateParams_captchaTemplateRequired|Test_New_returnsGetTemplateError|Test_GetTemplate|TestNew_BounceOnlyDoesNotConstructCaptcha|TestHandleBanServeHTTPContentType|TestHandleBanServeHTTPWithDifferentMethods|Test_ValidateParams$' ./...` — **pass**. Empty `CaptchaFilePath` fails `plugin.New` with `CaptchaFilePath: cannot be empty when CaptchaProvider is set` and does not open LAPI. Missing captcha file fails `ValidateParams` and `Client.New` (`no template file provided` / read error). Empty `BouncerBanFilePath` passes `ValidateParams`. Bounce-only `bouncer.New` does not construct a captcha client.
- Throwaway `TestExploreRepro_EmptyBanPathSilentAndEmptyBody` / `TestExploreRepro_ValidateParamsEmptyBanSilentMissingCaptchaFails` (run then deleted) — **pass**. `bouncer.New` with empty ban path logged no ban/template line; `banTemplate` stayed nil; GET `handleBanServeHTTP` wrote 403 and `""`. `ValidateParams` with a loadable captcha fixture and empty ban path logged no ban/template line. Bounce-only leftover `CaptchaFilePath=/captcha.html` passed `ValidateParams`.

**Not a failing test today:** dest never warns on empty ban path. `bouncer.New` skips `GetTemplate` when the path is empty and discards the error when the path is set (`pkg/bouncer/bouncer.go`). `ValidateParams` only `GetTemplate`s the ban file when the path is non-empty and returns that error (`pkg/configuration/configuration.go`).

### Today

```
plugin.New
  ├─ ValidateParams
  │     ├─ CaptchaEnabled false → skip captcha GetTemplate (unused default /captcha.html)
  │     ├─ CaptchaEnabled + empty path → FAIL CaptchaFilePath: cannot be empty...
  │     ├─ CaptchaEnabled + GetTemplate fail → FAIL (return that error)
  │     └─ BouncerBanFilePath set + GetTemplate fail → FAIL
  ├─ captcha.Open (only CaptchaEnabled)
  │     └─ Client.New → GetTemplate → return error (Valid already true, client discarded)
  └─ bouncer.New
        ├─ BouncerBanFilePath empty → banTemplate nil, no log
        └─ path set → GetTemplate, discard error
              │
              ▼
handleRemediationServeHTTP
  ├─ !subscribeCaptcha → WARN unsubscribed + ban
  ├─ nil / !Valid / not captcha kind → ban, no template-missing WARN
  └─ Valid client → captcha routing
handleBanServeHTTP
  ├─ banTemplate nil or HEAD → status, no body
  └─ template → execute
```

```
  captcha owner (CaptchaEnabled) --Open--> Client.New GetTemplate(CaptchaFilePath)
  bounce-only subscriber --------no Open--> unused default /captcha.html never read
  every bouncer.New -------------GetTemplate(BouncerBanFilePath) when non-empty
```

| Unit | Path | Job |
| --- | --- | --- |
| Config validation | `pkg/configuration/configuration.go` `ValidateParams` | Constructor gate. Captcha template required when `CaptchaEnabled`. Ban template checked only when path set. Empty ban path accepted. |
| GetTemplate | `pkg/configuration/configuration.go` | Shared file→template load. Empty path → `no template file provided`. |
| Captcha Client | `pkg/captcha/captcha.go` `Client.New` | Owner of captcha template. Returns `GetTemplate` error. Empty provider leaves `Valid` false. |
| Captcha Open | `pkg/captcha/session.go` `Open` / `newOwnerClient` | Reclaim owner. Calls `Client.New` with `cfg.CaptchaFilePath`. Only when `CaptchaEnabled`. |
| Plugin New | `plugin.go` `New` / `openOwned` | `ValidateParams` then `captcha.Open` when owned, then `bouncer.New`. `subscribeCaptcha` = bounce on + non-empty instance name. |
| Bouncer | `pkg/bouncer/bouncer.go` `New` | Owner of ban template. Does not read `CaptchaFilePath`. |
| Ban serve | `pkg/bouncer/bouncer.go` `handleBanServeHTTP` | Status + empty body when `banTemplate` nil. HEAD bodyless even when a template loaded. |
| Captcha fallback | `pkg/bouncer/bouncer.go` `handleRemediationServeHTTP` | Already bans when client is nil or `!Valid`. Unsubscribed WARN is a different stem. |
| Live spec | `openspec/specs/core_plugin_middleware_config-validation` | Provider-set captcha template fails `ValidateParams` and `Client.New`. Empty ban path is silent. |
| Usage | `knowledge/devdocs/core_plugin_middleware_config-validation.md` | Same rule: empty captcha path fails; ban stays "when path is set". |

### Call sites (bounded)

| Contract | Count | Roots searched |
| --- | --- | --- |
| `GetTemplate(` production | **4** (`validateCaptchaCredentialsAndTemplates` ban; `validateEnabledCaptchaSettings` captcha; `Client.New`; `bouncer.New`) | `pkg/configuration/configuration.go`, `pkg/captcha/captcha.go`, `pkg/bouncer/bouncer.go` |
| `Client.New(` production | **1** (`newOwnerClient`) | `pkg/captcha/session.go` |
| `captcha.Open(` | **1** (`openOwnedLeg` when `CaptchaEnabled`) | `plugin.go` |
| `bouncer.New(` | **1** (`plugin.go` `New`) | `plugin.go` |
| `ValidateParams(` | **1** (`plugin.go` `New`) | `plugin.go` |
| `handleRemediationServeHTTP` `!Valid` ban | **1** branch (`pkg/bouncer/bouncer.go`) | `pkg/bouncer/bouncer.go` |
| Pins of today's hard fail | **3** (`TestNew_RejectsEmptyCaptchaFilePath`, `Test_ValidateParams_captchaTemplateRequired`, `Test_New_returnsGetTemplateError`) | `zzz_plugin_test.go`, `pkg/configuration/zzz_configuration_test.go`, `pkg/captcha/zzz_siteverify_test.go` |

### Outside facts

In-tree: `knowledge/devdocs/core_plugin_middleware.md` (Captcha Client, Bouncer, two configuration axes), `core_plugin_middleware_config-validation.md`, `core_plugin_middleware_captcha-routing.md` (`!Valid` already bans). Research: `knowledge/research/ext_traefik_plugins_yaegi-constructor/` (`New` error means Traefik does not install the middleware). No new vendor clone.

### Language deltas (consume; no packet write)

No hard gap. **CaptchaEnabled**, **Captcha Client**, **Bouncer**, **Config validation**, **Unsubscribed captcha** already name the units. Ticket “bounce-only subscriber” is `CaptchaEnabled` false plus bounce on and a captcha instance name. Do not write packets this phase.

## Decisions

- **Seam:** Each owner warns at its constructor. `Client.New` / `Open` warns once when the captcha file is empty or not loadable, succeeds, and leaves `Valid` false so the existing ban fallback fires. `bouncer.New` warns once when the ban file is empty or not loadable and keeps `banTemplate` nil. `ValidateParams` stops failing `New` for either template; site key, secret, and gate secret stay required when a captcha provider is set.
- **Identity owner:** this change does not set or reconstruct client address, user, tenant, Host, or trust hop. No new owner.
- **Live contract:** `openspec/specs/core_plugin_middleware_config-validation` (Requirement: Provider set requires a loadable captcha template; Alone mode validates captcha templates). Propose MODIFIED those blocks plus empty/unloadable ban warn. Usage `knowledge/devdocs/core_plugin_middleware_config-validation.md` tracks the same rule. Not `no live contract`.
- **Rejected:** Warn from `bouncer.New` about `CaptchaFilePath` (false warn on a bounce-only subscriber whose unused default is `/captcha.html`). Warn from both (duplicate, and the bouncer half still false-warns). Keep `Valid` true and add a second “template missing” flag (parallel to existing `!Valid`). Embed `ban.html` / `captcha.html` (Out of scope). Per-request template-missing WARN (Out of scope). Relax site/secret/gate checks (Out of scope).

## Open questions

- Q: Exact warning text?
  Rank: additive asked — new log lines this change creates; Desired Warn once at startup that captcha responses will fall back to ban
  Decision: assumed — one-line WARN that names empty vs unloadable and the fallback; exact copy is implement
  By: explore

- Q: Does Client.New leave Valid false so the existing ban fallback fires, or stay Valid and choose ban elsewhere?
  Rank: bounded asked — Client.New Valid already consumed at 1 handleRemediationServeHTTP branch; Unknowns Explore owns that
  Decision: assumed — succeed and leave Valid false when the template is empty or not loadable; do not add a second template-missing flag
  By: explore

- Q: When BouncerBanFilePath is set but unloadable, is that the same warn-and-empty-body path as an empty ban path?
  Rank: bounded asked — 1 ValidateParams ban GetTemplate plus 1 bouncer.New discard; Desired Ban file empty or not loadable
  Decision: assumed — yes; warn once for empty or unloadable; do not fail New; keep empty body
  By: explore

- Q: Who emits the captcha-template warning so a bounce-only subscriber is not warned about unused default /captcha.html?
  Rank: bounded asked — existing owner split already has callers (1 Client.New, 1 captcha.Open, 1 bouncer.New, 2 ValidateParams GetTemplates); Open point / Unknowns names who emits
  Decision: resolved — captcha owner (Client.New / Open) emits the captcha-file warning; bouncer.New emits only the ban-file warning. Bounce-only never Opens captcha, so unused default /captcha.html is never read.
  By: explore
