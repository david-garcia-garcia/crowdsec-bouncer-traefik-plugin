# Explore
IssueKey: 2026-09-18-captcha-html-path-clobbers-file-path

## Concepts

DestBranch `plugin.New` aliases two deprecated HTML-path keys before `ValidateParams`:

```
BanFilePath == "" && BanHTMLFilePath != ""
        → BanFilePath = BanHTMLFilePath

CaptchaHTMLFilePath != ""
        → CaptchaFilePath = CaptchaHTMLFilePath
```

Ban fills only when the current key is empty. Captcha overwrites whenever the deprecated key is non-empty (`plugin.go:28-32`).

`CreateConfig` → `configuration.New()` pre-fills `CaptchaFilePath` = `/captcha.html` and `BanFilePath` = `""`. Traefik Yaegi decodes the operator map onto that pointer and does not set mapstructure `ZeroFields` (`ext_traefik_plugins_config-overlay`). A deploy that sets only `captchaHtmlFilePath` still arrives at `New` with `CaptchaFilePath` = `/captcha.html`. Today's overwrite is why that deploy serves the deprecated path. After an empty-guard, it keeps `/captcha.html`.

After the alias, `ValidateParams` compiles `CaptchaFilePath` via `GetTemplate` only when `CaptchaProvider` is set and the path is non-empty. `bouncer.New` passes the same field into `captcha.Client.New`, which compiles it again (and ignores `GetTemplate` errors — out of scope). Serve uses that compiled template.

```
CreateConfig (/captcha.html)
        │
        ▼
 Traefik mapstructure overlay
        │  missing captchaFilePath keeps default
        ▼
 plugin.New alias
        │  dest: deprecated always wins if set
        │  wanted: fill only when current is empty
        ▼
 ValidateParams GetTemplate (provider set)
        ▼
 captcha.Client.New(captchaTemplatePath)
        ▼
 ServeHTTP captcha page
```

`TestHunt_captchaFilePathWinsOverDeprecatedHTMLPath` is not on dest (`go test -run TestHunt_…` → no tests to run). Plugin-package tests in `zzz_plugin_test.go` use `TestNew_*`. No captcha-path spec leaf. Alias lives in `New` (`core_plugin_middleware_bouncer`), not in `ValidateParams` (`core_plugin_middleware_config-validation`).

In-repo consumers that set only the deprecated key:

- `tests/e2e/mock/scenarios/captcha/dynamic.yml` → scenario `captcha.html` (`E2E_CAPTCHA_PAGE_MARKER`). `run.sh` asserts that marker. Bundled `captcha.html` does not have it.
- `tests/e2e/real/docker-compose.test.yml` → `/e2e-captcha.html` (dummy), while `/captcha.html` is also mounted.
- `examples/captcha` and `examples/custom-captcha` set `captchaHTMLFilePath=/captcha.html` (same as the default). README rewrites are out of scope.

Reclaim / identity: this change only copies a config path. Do not add `sync.Once` or reconstruct client address.

**Not reproduced** as a failing unit test (hunt test absent). Overwrite is observed at `plugin.go:31-32`. Overlay + default is observed from Traefik `createConfig` + `configuration.New`.

No active OpenSpec change. Propose: change name `captcha-html-path-clobbers-file-path`. Fold the SHALL onto `core_plugin_middleware_bouncer` (New alias). Do not invent a captcha-path leaf. Do not fold into config-validation (that leaf is `ValidateParams`).

## Decisions

- Alias captcha like ban: copy `CaptchaHTMLFilePath` onto `CaptchaFilePath` only when `CaptchaFilePath == ""`.
- When both keys are set, keep `CaptchaFilePath`. Compile and serve follow that field.
- Do not treat the `/captcha.html` default as empty. Do not change the default. Deprecated-only Traefik YAML that never clears `captchaFilePath` keeps `/captcha.html` after the fix. Ticket bound that.
- Do not remove or rename `captchaHtmlFilePath`.
- Regression in `zzz_plugin_test.go`: `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath`. After `New`, assert mutated `config.CaptchaFilePath` equals the current path when both are set. `CaptchaProvider` stays empty so `GetTemplate` is skipped. Optional sibling: empty current + non-empty deprecated fills.
- Implement retargets mock + real e2e deprecated-only keys to `captchaFilePath` so they still compile the scenario/dummy template. Same defect. Leave README and examples.

## Open questions

- Q: Who already owns identity (client address, user, tenant, Host, trust hop)?
  Decision: resolved — none in this change. The work only copies `CaptchaFilePath`. Reuse `pkg/ip.GetRemoteIP` / Host as they stand. Do not reconstruct them.
  By: explore

- Q: Does Traefik overlay leave `CaptchaFilePath` as `""` when only `captchaHtmlFilePath` is set?
  Decision: resolved — no. `CreateConfig` pre-fills `/captcha.html`. Traefik mapstructure does not set `ZeroFields`, so a missing `captchaFilePath` keeps that default (`ext_traefik_plugins_config-overlay`).
  By: explore

- Q: Should the missing hunt test keep the `TestHunt_` name?
  Decision: resolved — no. Name it `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` in `zzz_plugin_test.go`, matching existing `TestNew_*` plugin tests (`std_go_test_zzz-prefix`).
  By: explore

- Q: Empty-guard plus the non-empty default makes deprecated-only Traefik deploys keep `/captcha.html`. Proceed anyway?
  Decision: resolved — yes. Ticket asks for the ban-shaped guard and bounds the defect to both-set current wins. Do not special-case the default.
  By: explore

- Q: In-repo e2e sets only `captchaHtmlFilePath` and asserts a custom template. Update those keys?
  Decision: resolved — yes. Point mock `dynamic.yml` and real compose labels at `captchaFilePath`. Mock `run.sh` requires `E2E_CAPTCHA_PAGE_MARKER`, which bundled `/captcha.html` does not have. Leave README and examples (out of scope; examples already use `/captcha.html`).
  By: explore

- Q: How should the regression prove compile and serve, not only the alias assignment?
  Decision: assumed — after `New`, assert `config.CaptchaFilePath` is the current path. That is the field `ValidateParams` compiles (when provider is set) and `captcha.Client.New` serves. Do not add a captcha ServeHTTP body test.
  By: explore

- Q: Which spec leaf hosts the alias SHALL?
  Decision: assumed — propose folds onto `core_plugin_middleware_bouncer` (`New` alias). Not `core_plugin_middleware_config-validation` (`ValidateParams`). Not a new captcha-path leaf.
  By: explore
