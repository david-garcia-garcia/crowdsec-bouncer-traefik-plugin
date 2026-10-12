## Why

This plugin already reclaim-binds LAPI, AppSec, and captcha. Operators who want OWASP CRS in the same Traefik process still have to load a second plugin (`traefik-modsecurity`), and a down AppSec listener with default `bouncerAppsecFailureAction: ban` keeps banning every request. Absorb that plugin as a fourth leg and copy its admission gate onto AppSec so a down listener stops taking ingress down.

## What Changes

- Add a ModSecurity reclaim leg beside LAPI, AppSec, and captcha. Own (`modsecEnabled`) vs bounce (`bouncerEnabled` + `modsecInstanceName`) stay independent. JSON stems `modsec*`. Not a replacement for AppSec. Not a second Traefik plugin.
- Inspect protocol stays the source sidecar contract: copy the request to `modsecUrl`; 2xx allow; 3xx/4xx copy the block page; 5xx is a WAF failure, not a block. Do not speak CrowdSec AppSec JSON on this leg.
- Per-router `bouncerModsecFailMode` (`open` default, `close` empty HTTP 502) on the Bouncer. The admission gate stays on the shared ModSec Client.
- Fold source `bypassRules` into `bouncerActionRules`: token `bypassModsec`; `bypass` also skips ModSec. No parallel skip list.
- Import utilities `backendbackoff.Gate` onto `appsec.Client` (one gate per listener). Do not copy Gate into this repo. Default `bouncerAppsecFailureAction` stays `ban` for an admitted miss. After the gate trips, skipped requests do not call AppSec and continue (`next`, then ModSec if subscribed).
- AppSec Client backoff knobs: `appsecUnhealthyBackOffPeriodSecs` default **30** (`0` disables), threshold default 5, ratio default packaged 0.30, max backoff default = base. Those knobs join the AppSec ownership key.
- ModSec Client backoff knobs default **0** (gate unused) because `failMode` default `open` already does not take ingress down.
- `modsecBodyLimit` omitted default 8 MiB (source CreateConfig). `0` is unlimited, same as `appsecBodyLimit` (not source Prepare, which treated `0` as omit).
- New Pester domain `modsec` (CI matrix fourth job). Compose adds an inspect-only Apache CRS sidecar first. Port source families that map: allow, CRS block, body-size 413, deny-verbs-with-body, failMode, backoff skip, action-rule skip. Do not port bombardier benches.
- README documents ModSec as a leg of this plugin. Traefik Security no longer lists `traefik-modsecurity` as a sibling. Geoblock and Rate Limit stay.
- **BREAKING** (behavior, no YAML alias): after AppSec backoff trips, a down AppSec no longer applies `bouncerAppsecFailureAction` on skipped requests. Operators who needed every request banned while AppSec was down must set `appsecUnhealthyBackOffPeriodSecs: 0`.

## Capabilities

### New Capabilities

- `core_plugin_modsecurity_client`: reclaim value for one CRS sidecar listener; ownership key; HTTP client; admission gate; deny-verbs-with-body; body limit and pool.
- `core_plugin_modsecurity_inspect`: copy-then-classify protocol (2xx / 3xx-4xx / 5xx), Host and header trust, copied block page, inbound cancel, local 413/400.

### Modified Capabilities

- `core_plugin_middleware_bouncer`: fourth `atomic.Value` binding; ServeHTTP order LAPI then AppSec then ModSec; action-rule token `bypassModsec`; `bypass` skips ModSec; missing subscribed ModSec uses failMode; structured header `ban:modsec`; New Open/rollback includes this group.
- `core_plugin_middleware_instance-slots`: fourth reclaim group `modsec` on the existing alias table; owner Open + SetAlias; empty-name fill when owned; exclusive publish and multi-leg rollback include this group.
- `core_plugin_middleware_config-validation`: `modsec*` own-axis and owner-read keys; open-vs-subscribe matrix includes ModSec; enabled ModSec requires `modsecUrl`; `bypassModsec` is a valid action token; `bouncerModsecFailMode` enum.
- `core_plugin_appsec_failure-action`: backoff is an extra layer; default `ban` remains for an admitted miss; gate skip is pass and MUST NOT apply FailureAction.
- `core_plugin_appsec_client`: ownership key includes backoff knobs; Client owns one `backendbackoff.Gate`; Close the Gate on Client Close.
- `build_e2e_pester_crowdsec-stack`: Pester domain `modsec`; CI matrix value `modsec`; inspect-only CRS sidecar; ported source families.

## Impact

- `plugin.go` — fourth `legModsec` in `openOwned` / `claimOwned` / `Watch` / rollback (do not rewrite into an N-leg registry).
- `pkg/modsecurity/` — new package absorbed from `traefik-modsecurity@e860d249` `pkg/modsecurity`, dest-shaped.
- `pkg/bouncer/` — fourth binding, `ReceiveModSec`, `serveModSec` after AppSec, action-rule skip.
- `pkg/appsec/` — Gate on Client; Query Allow then Report.
- `pkg/httprule/action.go` — `bypassModsec`; `bypass` sets SkipModsec.
- `pkg/configuration/configuration.go` — `modsec*` and AppSec backoff knobs.
- `tests/e2e/real/` — `PesterDomains.ps1`, compose CRS sidecar, `modsec*.Tests.ps1`.
- `.github/workflows/e2e.yml` — matrix `domain: [lapi, appsec, lifecycle, modsec]`.
- `README.md` — whole-project capabilities including ModSec config; drop sibling plugin listing.
- `go.mod` / vendor — import `traefik-middleware-utilities/backendbackoff` at dest pin `v1.0.7`.
- Usage packets fold on implement / `opd-devdocsimpact`. Do not write them in propose.
