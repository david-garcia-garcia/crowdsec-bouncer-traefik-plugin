## Context

Bug-hunt findings grouped three defects on the same `Bouncer.New` / `ServeHTTP` surface. Validation already checks checkers and ban templates; `New` re-calls and ignores errors. Appsec mode returns before captcha init while validation allows appsec failure-action captcha.

## Goals / Non-Goals

**Goals**
- Fix captcha init guard for appsec mode.
- Fail `New` on checker/template errors.
- Cover critical ServeHTTP branches with stub clients.

**Non-Goals**
- Configuration validation changes (reject appsec+captcha at validate time).
- Plugin constructor rollback.
- Captcha handler internals (`Validate`, provider HTTP).

## Decisions

- **Appsec captcha init**: run `captchaClient.New` when mode is appsec AND `EffectiveFailureAction(CrowdsecAppsecFailureAction) == captcha` AND `CaptchaProvider != ""`. Non-appsec modes keep existing always-init behavior.
- **Init errors**: return wrapped errors from `New` for checker and ban-template failures (same as captcha init failure).
- **Tests**: construct `Bouncer` directly with `lapi.NewTestServeHTTPLapiClient` and memory/redis cache fixtures; no plugin-level integration required for new cases.

## Risks / Trade-offs

- Operators invoking `Bouncer.New` without prior `ValidateParams` now get errors instead of degraded runtime — intended fail-closed behavior.
