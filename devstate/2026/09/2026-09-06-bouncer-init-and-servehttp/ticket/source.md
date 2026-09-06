# Finding
slug: bouncer-init-and-servehttp
component: bouncer
severity: bug
title: Appsec mode skips captcha init; New ignores checker/template errors; ServeHTTP untested

## Problem
`pkg/bouncer` constructor and request path:

1. `crowdsecMode: appsec` skips `captchaClient.New`, so `crowdsecAppsecFailureAction: captcha` validates then bans instead of serving captcha.
2. `NewChecker` and `GetTemplate` errors are discarded; handler can start with broken IP trust or empty ban pages.
3. No ServeHTTP / `handleRemediationServeHTTP` tests (stream unhealthy, redis unreachable, captcha remediation, failure-action captcha).

## Evidence
Sibling files: `appsec-mode-skips-captcha-init.md`, `new-ignores-init-errors.md`, `servehttp-branches-untested.md`.

## Current behavior
Appsec-only routers never initialize captcha. Init errors are ignored. Request branches are only covered indirectly in plugin_test (live ban/allow, trusted-IP).

## Desired
Initialize captcha when failure-action captcha can run, including appsec mode. Surface `NewChecker`/`GetTemplate` errors from `New`. Add ServeHTTP tests for the untested remediation branches.

## Grouped with this file
- appsec-mode-skips-captcha-init
- new-ignores-init-errors
- servehttp-branches-untested

## Out of scope
Plugin constructor rollback (plugin ticket). Captcha handler internals (captcha ticket).
