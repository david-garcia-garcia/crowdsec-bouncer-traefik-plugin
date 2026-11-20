## Why

This plugin already reclaim-binds LAPI, AppSec, and captcha. Operators who want OWASP CRS in the same Traefik process still have to load a second plugin (`traefik-modsecurity`), and a down AppSec listener with default `bouncerAppsecFailureAction: ban` keeps banning every request. Absorb that plugin as a fourth leg and copy its admission gate onto AppSec so a down listener stops taking ingress down.

## What Changes

- Add a ModSecurity reclaim leg beside LAPI, AppSec, and captcha. Own (`modsecEnabled`) vs bounce (`bouncerEnabled` + `modsecInstanceName`) stay independent. JSON stems `modsec*`. Not a replacement for AppSec. Not a second Traefik plugin.
- Inspect protocol stays the source sidecar contract: copy the request to `modsecUrl`; 2xx allow; 3xx/4xx copy the block page; 5xx is a WAF failure, not a block. Do not speak CrowdSec AppSec JSON on this leg.
- Per-router `bouncerModsecFailureAction` (`passthrough` default, `ban`, `captcha`) on the Bouncer, validated like the LAPI and AppSec failure actions. `ban` writes the ban template with reason `MODSEC` and `ban:modsec-failure`; `captcha` serves the router captcha with `captcha:modsec-failure`. The admission gate stays on the shared ModSec Client.
- Fold source `bypassRules` into `bouncerActionRules`: token `bypassModsec`; `bypass` also skips ModSec. No parallel skip list.
- Import utilities `backendbackoff.Gate` onto `appsec.Client` (one gate per listener). Do not copy Gate into this repo. Default `bouncerAppsecFailureAction` stays `ban` for an admitted miss. After a gate trips, skipped requests do not call that WAF and continue without its failure action (AppSec skip: then ModSec if subscribed; ModSec skip: `next`). Each gate logs `backoff started` once and `backoff ended` once per outage, never per skipped request.
- One backoff knob per leg: `appsecUnhealthyBackOffPeriodSecs` default **30** and `modsecUnhealthyBackOffPeriodSecs` default **0** (`0` disables; ModSec default `passthrough` already does not take ingress down). The trip rule is fixed in `pkg/admission` (5 failures in a row, failure ratio 0.30) and the cooldown does not grow. The period joins that leg's ownership key.
- `modsecBodyLimit` omitted default 8 MiB (source CreateConfig). It must be at least 1 when ModSec is owned. No unlimited value: the body is held in memory.
- No method list for bodies (source `denyVerbsWithBody` is not ported). Any readable body goes to the sidecar; CRS 920170/920171 block a body on GET/HEAD.
- New Pester domain `modsec` (CI matrix fourth job): `modsec.Tests.ps1` (ModSec alone), `waf_dual.Tests.ps1` (AppSec and ModSec on one router), `waf_backoff.Tests.ps1` (both gates through a real outage and recovery; the AppSec default-gate case moves here). Compose adds inspect-only Apache CRS sidecars `waf` and `waf-flaky`, an AppSec proxy `appsec-flaky`, and AppSec listener 7424. Port source families that map: allow, CRS block, body-size 413, failure actions, backoff skip, action-rule skip. Do not port bombardier benches.
- Runnable example `examples/modsecurity` (`make run_modsecurity`).
- README documents ModSec as a leg of this plugin (section "ModSecurity (OWASP CRS)"). Traefik Security no longer lists `traefik-modsecurity` as a sibling. Geoblock and Rate Limit stay.
- **BREAKING** (behavior, no YAML alias): after AppSec backoff trips, a down AppSec no longer applies `bouncerAppsecFailureAction` on skipped requests. Operators who needed every request banned while AppSec was down must set `appsecUnhealthyBackOffPeriodSecs: 0`.

## Capabilities

### New Capabilities

- `core_plugin_modsecurity_client`: reclaim value for one CRS sidecar listener; ownership key; HTTP client; admission gate; no method list for bodies; body limit.
- `core_plugin_modsecurity_inspect`: copy-then-classify protocol (2xx / 3xx-4xx / 5xx), `Inspect` returns the verdict and never writes, Host and header trust, copied block page, failure action, gate skip, inbound cancel, local 413, debounced unavailable log.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: fourth `atomic.Value` binding; ServeHTTP order LAPI then AppSec then ModSec; action-rule token `bypassModsec`; `bypass` skips ModSec; missing subscribed ModSec uses `bouncerModsecFailureAction`; structured headers `ban:modsec`, `ban:modsec-failure`, `captcha:modsec-failure`; New Open/rollback includes this group.
- `core_plugin_middleware_instance-slots`: fourth reclaim group `modsec` on the existing alias table; owner Open + SetAlias; empty-name fill when owned; exclusive publish and multi-leg rollback include this group.
- `core_plugin_middleware_config-validation`: `modsec*` own-axis and owner-read keys; open-vs-subscribe matrix includes ModSec; enabled ModSec requires `modsecUrl`; `modsecBodyLimit` at least 1 when owned; `bypassModsec` is a valid action token; `bouncerModsecFailureAction` failure-action enum; backoff periods non-negative.
- `core_plugin_appsec_failure-action`: backoff is an extra layer; default `ban` remains for an admitted miss; gate skip is pass and MUST NOT apply FailureAction.
- `core_plugin_appsec_client`: ownership key includes the backoff period; Client owns one `backendbackoff.Gate`; Close the Gate on Client Close.
- `build_e2e_pester_crowdsec-stack`: Pester domain `modsec`; CI matrix value `modsec`; inspect-only CRS sidecars; AppSec and ModSec on one router; both gates through a real outage.

## Impact

- `plugin.go` — fourth `legModsec` in `openOwned` / `claimOwned` / `Watch` / rollback (do not rewrite into an N-leg registry).
- `pkg/modsecurity/` — new package absorbed from `traefik-modsecurity@e860d249` `pkg/modsecurity`, dest-shaped.
- `pkg/bouncer/` — fourth binding, `ReceiveModSec`, `serveModSec` after AppSec, action-rule skip.
- `pkg/admission/` — shared gate wrapper with the fixed trip rule and the two transition log lines.
- `pkg/appsec/` — Gate on Client; Query Allow then Report.
- `pkg/httprule/action.go` — `bypassModsec`; `bypass` sets SkipModsec.
- `pkg/configuration/configuration.go` — `modsec*`, `bouncerModsecFailureAction`, and the two backoff periods; `ReasonMODSEC`.
- `pkg/lapi/client_metrics.go` — usage-metrics origin `plugin:modsec_failure`.
- `tests/e2e/real/` — `PesterDomains.ps1`, compose CRS sidecars and AppSec proxy, `modsec.Tests.ps1`, `waf_dual.Tests.ps1`, `waf_backoff.Tests.ps1` (replaces `appsec_backoff.Tests.ps1`).
- `examples/modsecurity/`, `Makefile` — runnable example.
- `.github/workflows/e2e.yml` — matrix `domain: [lapi, appsec, lifecycle, modsec]`.
- `README.md` — whole-project capabilities including ModSec config; drop sibling plugin listing.
- `go.mod` / vendor — import `traefik-middleware-utilities/backendbackoff` at dest pin `v1.0.7`.
- Usage packets fold on implement / `opd-devdocsimpact`. Do not write them in propose.
