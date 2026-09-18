# Empty `captchaFilePath` with a captcha provider panics on the first challenge

IssueKey: 2026-09-18-plugin-constructor-rollback-appsec-captcha
Size: large
Action: note

## Why this follow-up

`captcha.Client.New` takes the template from `configuration.GetTemplate(captchaTemplatePath)` and
**drops the error** (`pkg/captcha/captcha.go:89`). `GetTemplate("")` returns a nil template, so the
client comes back with `Valid` true and `template` nil. The first unsolved visitor reaches
`Client.ServeHTTP`, which calls `c.template.Execute(...)` on that nil pointer and panics.

Startup validation does not catch it: `validateEnabledCaptchaSettings` returns early when
`captchaFilePath` is empty (`pkg/configuration/configuration.go:393-395`), so an explicitly empty
path is accepted. A *missing* file is rejected, because `GetTemplate` then errors on the read — it is
only the empty value that slips through.

This is pre-existing and mode-independent. It is recorded here because this change makes appsec mode
one more way to reach it: `crowdsecAppsecFailureAction: captcha` now serves the challenge there too.

## Why it was not taken

Outside this ticket's five deliverables, and it is a behaviour change on the captcha constructor
(either `ValidateParams` starts rejecting a config it accepts today, or `captcha.Client.New` starts
returning an error it currently swallows). Both need the owner's call on which side pays.

## Risks

An operator who sets `captchaProvider` and blanks `captchaFilePath` gets a Traefik panic on the
first challenged request instead of a startup error — the worst place to find out.

## Context

- `pkg/captcha/captcha.go:89` drops the `GetTemplate` error.
- `pkg/captcha/captcha.go:116-129` executes the template unconditionally.
- `pkg/configuration/configuration.go:393-395` accepts the empty path.
- Default is `captchaFilePath: /captcha.html`, so the default deployment is unaffected.
