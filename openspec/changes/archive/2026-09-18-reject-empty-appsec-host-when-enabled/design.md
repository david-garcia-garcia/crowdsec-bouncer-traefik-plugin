## Context

See proposal.md for motivation. `ValidateParams` already calls `validateAppsecURLKeyAndTLS` in every non-alone mode, including when AppSec is off. That helper only asks `validateURL` whether `http.NewRequest` accepts `scheme://host/path`. Empty `CrowdsecAppsecHost` becomes `http:///` and returns nil. `CrowdsecAppsecHost` is not in `validateParamsRequired`. `New()` still defaults the host to `crowdsec:7422`. Listener host stays `Config.CrowdsecAppsecHost` (`appsec.identity`, `Query`); this change does not reconstruct it.

## Goals / Non-Goals

**Goals:**
- Fail startup when AppSec is enabled and the AppSec listener host is missing.
- Keep disabled-AppSec empty host and LAPI `validateURL` callers unchanged.

**Non-Goals:**
- Host-required change inside shared `validateURL`.
- AppSec URL checks in `alone` (sister ticket).
- Failure-action, Query, or Bouncer remediations.
- Extra TrimSpace rule (whitespace-only already fails `validateURL`).
- Putting `CrowdsecAppsecHost` on `validateParamsRequired` (that would reject disabled-AppSec empty host).

## Decisions

1. **Fix site** — in `validateAppsecURLKeyAndTLS`, when `CrowdsecAppsecEnabled`, reject a missing AppSec host. Alternative: require a host in `validateURL` — rejected; that would also fail disabled-AppSec empty host and LAPI callers. Alternative: add the key to `validateParamsRequired` — rejected for the same disabled-AppSec reason.
2. **What “missing” means** — empty `CrowdsecAppsecHost`, and a constructed AppSec URL whose `Host` is empty after `http.NewRequest` accepts it (`http:///` ). Same helper already builds that URL; do not add a second parser.
3. **Tests** — two `ValidateParams` cases in `zzz_configuration_test.go`: enabled + empty host errors; disabled + empty host still passes. Hunt name `TestHunt_ValidateParams_rejectsEmptyAppsecHostWhenEnabled` is not required.

## Risks / Trade-offs

- [Stricter startup] Operators who enable AppSec and clear the host will fail `plugin.New` instead of serving a ban-on-every-request site. → Intended; default `New()` host is unchanged.
- [Alone + AppSec enabled] still skips this helper. → Out of scope; sister ticket owns that skip.

## Migration Plan

None. Default configs keep `crowdsec:7422`. Only an explicit empty host with AppSec on starts failing.

## Open Questions

None — ticket decisions stand.
