# Requirement
IssueKey: 2026-09-18-appsec-empty-host-accepted

## Problem
ValidateParams accepts `crowdsecAppsecEnabled: true` with an empty `CrowdsecAppsecHost`. `plugin.New` then starts. Every AppSec Query is unreachable; default AppSec failure action bans the site.

## Current (code)
- `plugin.New` calls `ValidateParams` before AppSec Open. `plugin.go`
- Non-alone modes always call `validateAppsecURLKeyAndTLS`, including when AppSec is off. `pkg/configuration/configuration.go`
- `validateAppsecURLKeyAndTLS` checks AppSec URL format only via `validateURL`. `pkg/configuration/configuration.go`
- `validateURL` builds `scheme://host/path` and accepts whatever `http.NewRequest` accepts. Empty host becomes `http:///` and returns nil. `pkg/configuration/configuration.go`
- `CrowdsecAppsecHost` is not in `validateParamsRequired`. `pkg/configuration/configuration.go`
- `New()` defaults host to `crowdsec:7422` and `CrowdsecAppsecFailureAction` to `ban`. `pkg/configuration/configuration.go`
- Enabled AppSec Opens a Client and returns a Bouncer. `plugin.go`
- Query builds the listener URL from the stored host; `Do` on that empty-host URL is unreachable and the default failure action returns an error. `pkg/appsec/query.go`
- `applyAppsecServeHTTP` bans on Query error (`ReasonAPPSEC`). `pkg/bouncer/bouncer.go`
- `Test_validateURL` covers a valid host and a spaced host only. `pkg/configuration/zzz_configuration_test.go`
- `TestHunt_ValidateParams_rejectsEmptyAppsecHostWhenEnabled` is not in this tree. not found

## Desired
- When AppSec is enabled, reject an empty `crowdsecAppsecHost` and any AppSec URL that `http.NewRequest` accepts only because the host is missing.
- Include a regression test.
- Bound the ask to this defect only.

## Affected
- `pkg/configuration/configuration.go`
- `pkg/configuration` tests (regression)

## Out of scope
- Rejecting an empty AppSec host when AppSec is disabled
- Changing LAPI `validateURL` or the already-required `CrowdsecLapiHost`
- Adding AppSec URL checks in `alone` mode (ValidateParams skips `validateLapiAndAppsecConnection` there)
- Changing default `CrowdsecAppsecFailureAction` or Query/Bouncer remediations
- Other ValidateParams hunt items

## Unknowns
- The named hunt proof test is not committed; later phases add an in-tree regression test
- Whether a whitespace-only host should be treated as empty (ticket said empty)

## Tensions
- Ticket names `validateURL` as the cause; the asked fix is gated on AppSec enabled, so a general host-required change in `validateURL` would also reject disabled-AppSec empty host and is extra
- `alone` plus AppSec enabled never reaches `validateAppsecURLKeyAndTLS`; ticket bound the ask to the `validateURL` accept path
- Official CrowdSec spec default AppSec failure is passthrough; this plugin defaults to `ban` (`New()`). Ticket uses this plugin’s default
