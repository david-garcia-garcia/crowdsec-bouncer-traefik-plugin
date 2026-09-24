# Explore

## Concepts

Owner-read captcha knobs sit on `configuration.Config` under the `BouncerCaptcha` / `bouncerCaptcha*` stem even though `pkg/captcha` is the piece that reads them. `CaptchaEnabled` / `CaptchaInstanceName` already use the captcha stem. Bounce-decision fields stay on the bouncer stem (a value may be the word `captcha`). This change moves the seventeen owner-read fields and their JSON tags onto `Captcha` / `captcha*`. No aliases. Product is beta; the public-key break is the job.

Units this change would touch:

- `configuration.Config` — `pkg/configuration/configuration.go` — public Go fields, JSON tags, `CreateConfig` / `configuration.New` defaults, `GetVariable` lookup strings, `ValidateParams` error text, leftover-E2 gate (`validateOpenVsSubscribe` passes `secretPresent=false` for captcha).
- Captcha owner Open — `pkg/captcha/session.go` — `ownershipFrom` and `newOwnerClient` read `GetVariable("BouncerCaptchaSiteKey"|"BouncerCaptchaSecretKey"|"BouncerCaptchaGateSecret")` plus the other `cfg.BouncerCaptcha*` knobs.
- Live catalog — `openspec/specs/core_plugin_middleware_config-validation/spec.md` (and four sibling live specs that name the old stem as current contract).
- Operator surface — `README.md`, `examples/captcha/`, `examples/custom-captcha/`, real compose labels, mock e2e YAML.
- Usage packets — `knowledge/devdocs/core_plugin_middleware_config-validation.md` and seven siblings that still spell `bouncerCaptcha*` as how-to.

```
Traefik createConfig (mapstructure, field name, unused keys dropped)
        │
        ▼
configuration.Config  (Go field + json tag)
        │
        ├─ ValidateParams / GetVariable
        ├─ captcha.ownershipFrom / newOwnerClient
        └─ README / examples / e2e labels
```

Call sites that matter: **34** in-tree current-contract files (roots searched: worktree minus `openspec/changes/archive/` and other-run `devstate/`; patterns `BouncerCaptcha` and `bouncerCaptcha`). Go identifier matches on the same roots: **244** (`pkg/configuration/configuration.go` 58, `pkg/captcha/session.go` 28, configuration tests 111, `pkg/captcha/zzz_owner_test.go` 6, `pkg/lapi/zzz_session_test.go` 1, `pkg/bouncer/zzz_http_timeout_test.go` 4, root plugin tests 36). All 34 are migratable here. Outside this tree, operator YAML cannot be enumerated.

The 34 files:

- Code: `pkg/configuration/configuration.go`, `pkg/captcha/session.go`
- Tests: `pkg/configuration/zzz_configuration_test.go`, `pkg/configuration/zzz_http_timeout_test.go`, `pkg/configuration/zzz_origin_based_decision_remap_test.go`, `pkg/captcha/zzz_owner_test.go`, `pkg/lapi/zzz_session_test.go`, `pkg/bouncer/zzz_http_timeout_test.go`, `zzz_plugin_test.go`, `zzz_constructor_test.go`, `zzz_bouncer_logging_test.go`
- E2E: `tests/e2e/real/config/docker-compose.test.yml`, `tests/e2e/real/captcha.Tests.ps1`, `tests/e2e/mock/scenarios/captcha/dynamic.yml`, `tests/e2e/mock/scenarios/captcha-ban-origins/dynamic.yml`, `tests/e2e/mock/README.md`
- Live specs: `openspec/specs/core_plugin_middleware_config-validation/spec.md`, `openspec/specs/core_plugin_middleware_captcha-gate/spec.md`, `openspec/specs/core_plugin_middleware_bouncer/spec.md`, `openspec/specs/core_plugin_lapi_reclaim-key/spec.md`, `openspec/specs/build_e2e_pester_crowdsec-stack/spec.md`
- Usage: `knowledge/devdocs/core_plugin_middleware_config-validation.md`, `knowledge/devdocs/core_plugin_middleware.md`, `knowledge/devdocs/core_plugin_middleware_captcha-gate.md`, `knowledge/devdocs/core_plugin_middleware_captcha-routing.md`, `knowledge/devdocs/core_plugin_middleware_captcha-siteverify.md`, `knowledge/devdocs/core_plugin_lapi_origin-based-decision-remap.md`, `knowledge/devdocs/build_e2e_real.md`, `knowledge/devdocs/build_e2e_mock.md`
- Operator docs: `README.md`, `examples/captcha/docker-compose.yml`, `examples/captcha/README.md`, `examples/custom-captcha/docker-compose.yml`, `examples/custom-captcha/README.md`

Reproduce: **not reproduced** — no claimed failure. Path run: inventory search on the worktree. Evidence: `pkg/configuration/configuration.go` still declares the seventeen `BouncerCaptcha*` fields with `json:"bouncerCaptcha*"` (lines 75–91); live spec still SHALL-freezes `bouncerCaptcha*` (`openspec/specs/core_plugin_middleware_config-validation/spec.md`).

Outside facts used: in-tree `knowledge/research/ext_traefik_plugins_config-decode/` — Traefik v3.7.11 mapstructure-decodes by **field name** (not the json tag as a separate spelling); unused keys are dropped (`ErrorUnused` unset). After the rename, leftover `bouncerCaptcha*` never reaches `New`.

Seventeen fields (from the prepared ticket list; `CaptchaEnabled` / `CaptchaInstanceName` stay):

| Go now → after | JSON now → after |
|---|---|
| `BouncerCaptchaCustomChallengeURL` → `CaptchaCustomChallengeURL` | `bouncerCaptchaCustomChallengeUrl` → `captchaCustomChallengeUrl` |
| `BouncerCaptchaCustomJsURL` → `CaptchaCustomJsURL` | `bouncerCaptchaCustomJsUrl` → `captchaCustomJsUrl` |
| `BouncerCaptchaCustomKey` → `CaptchaCustomKey` | `bouncerCaptchaCustomKey` → `captchaCustomKey` |
| `BouncerCaptchaCustomResponse` → `CaptchaCustomResponse` | `bouncerCaptchaCustomResponse` → `captchaCustomResponse` |
| `BouncerCaptchaCustomValidateBody` → `CaptchaCustomValidateBody` | `bouncerCaptchaCustomValidateBody` → `captchaCustomValidateBody` |
| `BouncerCaptchaCustomValidateURL` → `CaptchaCustomValidateURL` | `bouncerCaptchaCustomValidateUrl` → `captchaCustomValidateUrl` |
| `BouncerCaptchaFilePath` → `CaptchaFilePath` | `bouncerCaptchaFilePath` → `captchaFilePath` |
| `BouncerCaptchaGateBindIP` → `CaptchaGateBindIP` | `bouncerCaptchaGateBindIp` → `captchaGateBindIp` |
| `BouncerCaptchaGateSecret` → `CaptchaGateSecret` | `bouncerCaptchaGateSecret` → `captchaGateSecret` |
| `BouncerCaptchaGateSecretFile` → `CaptchaGateSecretFile` | `bouncerCaptchaGateSecretFile` → `captchaGateSecretFile` |
| `BouncerCaptchaGracePeriodSeconds` → `CaptchaGracePeriodSeconds` | `bouncerCaptchaGracePeriodSeconds` → `captchaGracePeriodSeconds` |
| `BouncerCaptchaProvider` → `CaptchaProvider` | `bouncerCaptchaProvider` → `captchaProvider` |
| `BouncerCaptchaSecretKey` → `CaptchaSecretKey` | `bouncerCaptchaSecretKey` → `captchaSecretKey` |
| `BouncerCaptchaSecretKeyFile` → `CaptchaSecretKeyFile` | `bouncerCaptchaSecretKeyFile` → `captchaSecretKeyFile` |
| `BouncerCaptchaSiteKey` → `CaptchaSiteKey` | `bouncerCaptchaSiteKey` → `captchaSiteKey` |
| `BouncerCaptchaSiteKeyFile` → `CaptchaSiteKeyFile` | `bouncerCaptchaSiteKeyFile` → `captchaSiteKeyFile` |
| `BouncerCaptchaSiteverifyHTTPTimeoutSeconds` → `CaptchaSiteverifyHTTPTimeoutSeconds` | `bouncerCaptchaSiteverifyHttpTimeoutSeconds` → `captchaSiteverifyHttpTimeoutSeconds` |

## Decisions

- Chosen seam: rename the seventeen `Config` Go fields and JSON tags; move `GetVariable` strings, validation errors, live-spec SHALLs, usage how-to, README, examples, e2e labels, and tests with the fields. Reorder the struct so the new `Captcha*` block sits with `CaptchaEnabled` / `CaptchaInstanceName` (existing “alphabetical by json tag” rule on `Config`).
- Rejected: old-key aliases — Out of scope and Desired “Do not keep old-key aliases.” Traefik matches the field name; a json-only alias would not decode anyway (`ext_traefik_plugins_config-decode`).
- Rejected: keep Go names and change only JSON tags — same research; Yaegi decode would still bind `BouncerCaptcha*`.
- Rejected: nest a `captcha:` map — would break the flat `Config` stem contract already live on `core_plugin_middleware_config-validation`.
- Rejected: rewrite archived OpenSpec change folders — Out of scope.
- Live contract: `openspec/specs/core_plugin_middleware_config-validation/spec.md` (stale SHALL that owner-read settings stay `bouncerCaptcha*`). Sibling live specs that name the old stem as current contract: `core_plugin_middleware_captcha-gate`, `core_plugin_middleware_bouncer`, `core_plugin_lapi_reclaim-key`, `build_e2e_pester_crowdsec-stack`. Propose MODIFIED those remaining promises. No new spec family. Active `openspec/changes/`: none.

## Open questions

- Q: Which in-tree files still spell `bouncerCaptcha*` / `BouncerCaptcha*` as current contract and must move with the fields?
  Rank: bounded asked — 34 current-contract files enumerated (roots: worktree minus archive and other-run `devstate/`; patterns `BouncerCaptcha` and `bouncerCaptcha`); Desired “Move GetVariable lookup strings, validation error text, README, e2e labels, and tests that name the old keys with the fields”
  Decision: resolved — migrate those 34. Leave archived OpenSpec folders and other-run `devstate/` alone.
  By: explore

- Q: After the stem move, should leftover owner-read captcha settings stay non-E2?
  Rank: additive incidental — no existing leftover-secret rule is being rewritten at scale; no criterion names leftover-secret classification
  Decision: assumed — leftover owner-read captcha knobs stay non-E2 (`validateOpenVsSubscribe` still passes `secretPresent=false` for captcha). Leftover `captchaInstanceName` stays E2. Dropped `bouncerCaptcha*` keys never reach `New`.
  By: explore

- Q: What is the operator blast radius outside this tree?
  Rank: structural asked — callers of the public YAML/label contract outside this tree cannot be enumerated; Problem “Breaking the public contract is accepted” and Desired “Do not keep old-key aliases”
  Decision: assumed — break the keys; no aliases; README BREAKING names the stem move. Operators must rename labels/YAML. Pre-prefix leftovers that already spelled `captchaFilePath` (before the 2026-09-23 bouncer prefix) start mapping again; current `bouncerCaptcha*` stops. That revival is a consequence of returning to the captcha stem, not an alias.
  By: explore

- Q: Who already owns client address, user, tenant, Host, or trust hop for this change?
  Rank: additive incidental — no criterion names identity reconstruction; this rename does not set those facts
  Decision: resolved — none. Gate bind still reads `clientRequest.remoteIP` from ServeHTTP (`pkg/ip.GetRemoteIP`). Do not reconstruct identity in configuration or captcha Open.
  By: explore
