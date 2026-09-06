# plugin-constructor-rollback (local spec)

Grouped findings: partial-constructor-no-rollback, appsec-mode-without-enabled-pass-through, untested-constructor-mode-branches.

## Problem

Root `plugin.go` `New` opens LAPI then AppSec then `bouncer.New`. If a later step fails, LAPI/AppSec reclaim holders and tickers are not rolled back. `crowdsecMode: appsec` with `crowdsecAppsecEnabled: false` builds a pass-through bouncer with neither LAPI nor AppSec. Constructor branches for alone, appsec-only, combined, and error returns are untested.

## Current behavior

Failed `appsec.Open` or `bouncer.New` after LAPI open leaves stream/live clients running. Invalid appsec-mode combo is a silent allow-all. Tests do not cover those branches.

## Desired

On any failure after a backend Open, close/drop those holders before returning. Reject or require AppSec when mode is `appsec` (do not ship a pass-through). Tests for alone, appsec-only, LAPI+AppSec, and constructor error rollback.

## Out of scope

Live/stream reclaim success paths already covered. Captcha template (other ticket). Bouncer ServeHTTP tests (bouncer ticket). Reclaim concurrent first-Open races (`pkg/reclaim`). Traefik cancel timing on failed constructors. Deep `ValidateParams` matrix (`pkg/configuration`). AppSec runtime query/failure-action (`pkg/bouncer`, `pkg/appsec`). E2e Traefik reload timing.
