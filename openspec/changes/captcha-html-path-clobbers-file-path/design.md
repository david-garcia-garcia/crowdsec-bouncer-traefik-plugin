## Context

See proposal.md — Why. Dest `plugin.New` aliases ban only when `BanFilePath` is empty, then aliases captcha whenever `CaptchaHTMLFilePath` is non-empty (`plugin.go`). `CreateConfig` pre-fills `CaptchaFilePath` = `/captcha.html`. Traefik mapstructure does not set `ZeroFields`, so a missing `captchaFilePath` keeps that default (`ext_traefik_plugins_config-overlay`). After the alias, `ValidateParams` compiles `CaptchaFilePath` when a provider is set, and `bouncer.New` passes the same field into `captcha.Client.New`.

## Goals / Non-Goals

**Goals:**
- Make the captcha alias match the ban empty-guard.
- Prove both-set current-wins on the mutated `config.CaptchaFilePath` after `New`.
- Keep mock and real e2e custom templates compiling after the guard.

**Non-Goals:**
- Removing or renaming `captchaHtmlFilePath`.
- Changing the `/captcha.html` default or treating that default as empty.
- A captcha ServeHTTP body test.
- Reconstructing client address, Host, or trust hop.
- README / examples / usage-doc rewrites.

## Decisions

1. Same `if` shape as ban: `CaptchaFilePath == "" && CaptchaHTMLFilePath != ""` then copy. Alternative considered: special-case the default so deprecated-only Traefik YAML still wins. Ticket bound both-set current-wins and asked for the ban-shaped guard; do not special-case `/captcha.html`.
2. Regression `TestNew_CaptchaFilePathWinsOverDeprecatedHTMLPath` in `zzz_plugin_test.go`. After `New`, assert `config.CaptchaFilePath` equals the current path. Leave `CaptchaProvider` empty so `GetTemplate` is skipped. Optional sibling: empty current + non-empty deprecated fills. Alternative considered: `TestHunt_*` name or a ServeHTTP compile/serve test. Existing plugin tests use `TestNew_*`; compile/serve already follow that field.
3. Retarget mock `dynamic.yml` and real compose labels from `captchaHtmlFilePath` to `captchaFilePath`. Same defect: those suites set only the deprecated key and assert a custom marker that bundled `/captcha.html` does not have. Leave README and examples.

## Risks / Trade-offs

- Deprecated-only Traefik YAML that never clears `captchaFilePath` keeps `/captcha.html` after the fix. → Accepted. Overlay plus default is observed; ticket bound that.
- In-repo e2e would start serving the bundled page if keys stay deprecated-only. → Retarget those two keys in the same apply.

## Migration Plan

No operator migration. Operators who set both keys already get the current path after this change. Operators who set only the deprecated key and rely on today's overwrite must also set `captchaFilePath` (or clear it) if they need a non-default template.

## Open Questions

None — ticket decisions stand.
